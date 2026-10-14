using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 26 (spec §5 "Dispatch" as amended, decision R-7): a virtual or interface call runs the implementations the
/// solution creates: types built with `new`, registered in the DI container (type arguments, `typeof` pairs, factories,
/// descriptors, open generics, hosted services, decorators) or built by the framework (controllers, filters, hosted
/// services, views...). The class hierarchy stays the answer when no implementation is known, when the types come from
/// assembly scanning or reflection, and when the solution holds no registration at all. Shapes written anew from the
/// Microsoft.Extensions.DependencyInjection docs; Scrutor and Autofac are stood in for by small shims with their names.
public sealed class DiDispatchTests : TempDirs
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    /// Ten exporters behind one interface, each with its own sink; `expected(i)` marks the ones that must be reported.
    /// The controller gets the interface from the container.
    private static string Exporters(Func<int, bool> expected, string registration, string extra = "")
    {
        var code = new StringBuilder();
        code.AppendLine("using Microsoft.Extensions.DependencyInjection.Extensions;");
        if (extra.Contains("namespace Scrutor", StringComparison.Ordinal)) code.AppendLine("using Scrutor;");
        if (extra.Contains("namespace Autofac", StringComparison.Ordinal)) code.AppendLine("using Autofac;");
        code.AppendLine("public interface IExporter { void Export(string filter); }");
        for (var i = 0; i < 10; i++)
        {
            code.Append($"public class Exporter{i} : IExporter {{ private readonly SqlConnection _c = new(); ");
            code.Append($"public void Export(string filter) => _c.Execute(\"SELECT * FROM t{i} WHERE \" + filter);");
            code.AppendLine(expected(i) ? " } /*sink*/" : " }");
        }
        code.AppendLine("""
            public class ExportController : ControllerBase
            {
                private readonly IExporter _exporter;
                public ExportController(IExporter exporter) => _exporter = exporter;
                public IActionResult Run(string q)
                {
                    _exporter.Export(q);
                    return Ok();
                }
            }
            public static class Registration
            {
                public static void Add(IServiceCollection services)
                {
            """);
        code.AppendLine(registration);
        code.AppendLine("    }");
        code.AppendLine("}");
        code.AppendLine(extra);
        return code.ToString();
    }

    private const string ScrutorShim = """
        namespace Scrutor
        {
            public interface ITypeSourceSelector { IImplementationTypeSelector FromAssemblyOf<T>(); }
            public interface IImplementationTypeSelector { IServiceTypeSelector AddClasses(); }
            public interface IServiceTypeSelector { IServiceCollection AsImplementedInterfaces(); }
            public static class ScrutorExtensions
            {
                public static IServiceCollection Scan(this IServiceCollection services, Action<ITypeSourceSelector> action) => services;
                public static IServiceCollection Decorate<TService, TDecorator>(this IServiceCollection services) where TDecorator : TService => services;
            }
        }
        """;

    private const string AutofacShim = """
        namespace Autofac
        {
            public class ContainerBuilder
            {
                public RegistrationBuilder RegisterAssemblyTypes(params System.Reflection.Assembly[] assemblies) => new RegistrationBuilder();
            }
            public class RegistrationBuilder
            {
                public RegistrationBuilder AsImplementedInterfaces() => this;
                public RegistrationBuilder As<TService>() => this;
            }
            public static class RegistrationExtensions
            {
                public static RegistrationBuilder RegisterType<TImplementer>(this ContainerBuilder builder) => new RegistrationBuilder();
            }
        }
        """;

    [Fact]
    public void A_wide_interface_resolves_to_its_one_registered_implementation()
    {
        var code = Exporters(i => i == 3, "services.AddScoped<IExporter, Exporter3>();");
        Expect(code);
        var stats = Snippet.Analyze(code).Stats;
        Assert.True(stats.DispatchNarrowed >= 1, $"narrowed {stats.DispatchNarrowed}");
        Assert.True(stats.DispatchByRegistrations >= 1, $"by registrations {stats.DispatchByRegistrations}");
    }

    [Fact]
    public void Every_registration_form_counts_and_the_unregistered_implementations_stay_quiet() => Expect(Exporters(i => i <= 8, """
                services.TryAddScoped<IExporter, Exporter0>();
                services.TryAddEnumerable(ServiceDescriptor.Transient<IExporter, Exporter1>());
                services.Add(new ServiceDescriptor(typeof(IExporter), typeof(Exporter2), ServiceLifetime.Scoped));
                services.AddKeyedSingleton<IExporter, Exporter3>("csv");
                services.AddSingleton(typeof(IExporter), typeof(Exporter4));
                services.AddTransient<Exporter5>();
                Wiring.AddService<IExporter, Exporter6>(services);
                services.TryAdd(ServiceDescriptor.Describe(typeof(IExporter), typeof(Exporter7), ServiceLifetime.Singleton));
                new Autofac.ContainerBuilder().RegisterType<Exporter8>().As<IExporter>();
        """, AutofacShim + """
        public static class Wiring
        {
            public static void AddService<TService, TImplementation>(IServiceCollection services)
                where TService : class where TImplementation : class, TService => services.AddScoped<TService, TImplementation>();
        }
        """));

    public static IEnumerable<object[]> Scans() => new[]
    {
        new object[] { "Scrutor", "services.Scan(s => s.FromAssemblyOf<ExportController>().AddClasses().AsImplementedInterfaces());", ScrutorShim },
        new object[] { "GetTypes", """
                    foreach (var type in typeof(ExportController).Assembly.GetTypes())
                        if (type.IsClass && !type.IsAbstract && type.Name.StartsWith("Exporter")) services.AddScoped(typeof(IExporter), type);
            """, "" },
        new object[] { "Autofac", "new Autofac.ContainerBuilder().RegisterAssemblyTypes(typeof(ExportController).Assembly).AsImplementedInterfaces();", AutofacShim },
        new object[] { "GetExports<T>", "foreach (var e in new PartHost().GetExports<IExporter>()) services.AddSingleton(e);", """
            public class PartHost
            {
                private readonly Type[] _types = typeof(PartHost).Assembly.GetExportedTypes();
                public IEnumerable<T> GetExports<T>() => GetExportTypes<T>().Select(Build).Where(o => o != null).Cast<T>();
                private IEnumerable<Type> GetExportTypes<T>()
                {
                    var wanted = typeof(T);
                    return _types.Where(t => !t.IsAbstract && wanted.IsAssignableFrom(t));
                }
                private static object? Build(Type type) => Activator.CreateInstance(type);
            }
            """ },
        new object[] { "Activator cast", """
                    foreach (var name in new[] { "Exporter8", "Exporter9" })
                        services.AddSingleton((IExporter)Activator.CreateInstance(Type.GetType(name)!)!);
            """, "" },
    };

    /// Scanning or reflection (the brief's Scrutor `Scan`, Autofac `RegisterAssemblyTypes`, a `GetTypes()` loop feeding
    /// `Add*`, a `GetExports<T>()` helper filtering by `typeof(T)`, an object made by `Activator` and cast to the
    /// interface) may register any implementation: every one is a target, the one registered by name included.
    [Theory]
    [MemberData(nameof(Scans))]
    public void Scanning_or_reflection_resolves_to_every_implementation(string form, string scan, string extra)
    {
        Assert.NotNull(form);
        var stats = Snippet.Analyze(Exporters(_ => true, "services.AddScoped<IExporter, Exporter3>();\n" + scan, extra)).Stats;
        Expect(Exporters(_ => true, "services.AddScoped<IExporter, Exporter3>();\n" + scan, extra));
        Assert.Equal(0, stats.DispatchNarrowed);
    }

    [Fact]
    public void A_factory_lambda_registers_the_type_it_builds() => Expect("""
        public interface IPaymentGateway { void Charge(string reference); }
        public class StripeGateway : IPaymentGateway
        {
            private readonly SqlConnection _c = new();
            public StripeGateway(string key) { }
            public void Charge(string reference) => _c.Execute("UPDATE p SET s = 1 WHERE r = '" + reference + "'"); /*sink*/
        }
        public class LedgerGateway : IPaymentGateway
        {
            private readonly SqlConnection _c = new();
            public void Charge(string reference) => _c.Execute("UPDATE l SET s = 1 WHERE r = '" + reference + "'"); /*sink*/
        }
        public class SandboxGateway : IPaymentGateway
        {
            private readonly SqlConnection _c = new();
            public void Charge(string reference) => _c.Execute("UPDATE x SET s = 1 WHERE r = '" + reference + "'");
        }
        public static class Gateways
        {
            public static IPaymentGateway Ledger() => new LedgerGateway();
        }
        public static class Registration
        {
            public static void Add(IServiceCollection services, IConfiguration config)
            {
                services.AddScoped<IPaymentGateway>(sp => new StripeGateway(config["Stripe:Key"]!));
                services.AddSingleton(sp => Gateways.Ledger());
            }
        }
        public class PayController : ControllerBase
        {
            private readonly IEnumerable<IPaymentGateway> _gateways;
            public PayController(IEnumerable<IPaymentGateway> gateways) => _gateways = gateways;
            public IActionResult Charge(string reference)
            {
                foreach (var g in _gateways) g.Charge(reference);
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_open_generic_registration_resolves_a_closed_interface_call_to_its_implementation() => Expect("""
        public interface IRepository<T> { IEnumerable<T> Find(string where); }
        public class EfRepository<T> : IRepository<T>
        {
            private readonly SqlConnection _c = new();
            public IEnumerable<T> Find(string where) => _c.Query<T>("SELECT * FROM t WHERE " + where); /*sink*/
        }
        public class DapperRepository<T> : IRepository<T>
        {
            private readonly SqlConnection _c = new();
            public IEnumerable<T> Find(string where) => _c.Query<T>("SELECT * FROM d WHERE " + where);
        }
        public class MemoryRepository<T> : IRepository<T>
        {
            private readonly SqlConnection _c = new();
            public IEnumerable<T> Find(string where) => _c.Query<T>("SELECT * FROM m WHERE " + where);
        }
        public class Order { }
        public static class Registration
        {
            public static void Add(IServiceCollection services) => services.AddScoped(typeof(IRepository<>), typeof(EfRepository<>));
        }
        public class OrdersController : ControllerBase
        {
            private readonly IRepository<Order> _orders;
            public OrdersController(IRepository<Order> orders) => _orders = orders;
            public IActionResult Find(string q) => Ok(_orders.Find("name = '" + q + "'"));
        }
        """);

    public static IEnumerable<object[]> Decorators() => new[]
    {
        new object[] { "services.AddScoped<IStore, SqlStore>();\n        services.Decorate<IStore, CachingStore>();", ScrutorShim },
        new object[] { "services.AddScoped<IStore>(sp => new CachingStore(new SqlStore()));", "" },
    };

    /// A decorator (Scrutor's `Decorate`, or a wrapper built by hand in a factory) runs, and so does the implementation it
    /// wraps; an implementation nobody registers stays out.
    [Theory]
    [MemberData(nameof(Decorators))]
    public void A_decorator_and_the_implementation_it_wraps_are_targets(string registration, string extra) => Expect($$"""
        using Scrutor;
        public interface IStore { void Save(string name); }
        public class SqlStore : IStore
        {
            private readonly SqlConnection _c = new();
            public void Save(string name) => _c.Execute("INSERT INTO s VALUES ('" + name + "')"); /*sink*/
        }
        public class CachingStore : IStore
        {
            private readonly SqlConnection _c = new();
            private readonly IStore _inner;
            public CachingStore(IStore inner) => _inner = inner;
            public void Save(string name)
            {
                _c.Execute("INSERT INTO cache VALUES ('" + name + "')"); /*sink*/
                _inner.Save(name);
            }
        }
        public class LegacyStore : IStore
        {
            private readonly SqlConnection _c = new();
            public void Save(string name) => _c.Execute("INSERT INTO legacy VALUES ('" + name + "')");
        }
        public static class Registration
        {
            public static void Add(IServiceCollection services)
            {
                {{registration}}
            }
        }
        public class StoreController : ControllerBase
        {
            private readonly IStore _store;
            public StoreController(IStore store) => _store = store;
            public IActionResult Save(string name)
            {
                _store.Save(name);
                return Ok();
            }
        }
        {{(extra.Length > 0 ? extra : "namespace Scrutor { }")}}
        """);

    [Fact]
    public void A_type_built_with_new_is_a_target_without_a_registration() => Expect("""
        public interface INotifier { void Notify(string to); }
        public class EmailNotifier : INotifier
        {
            private readonly SqlConnection _c = new();
            public void Notify(string to) => _c.Execute("INSERT INTO mail VALUES ('" + to + "')"); /*sink*/
        }
        public class SmsNotifier : INotifier
        {
            private readonly SqlConnection _c = new();
            public void Notify(string to) => _c.Execute("INSERT INTO sms VALUES ('" + to + "')"); /*sink*/
        }
        public class PushNotifier : INotifier
        {
            private readonly SqlConnection _c = new();
            public void Notify(string to) => _c.Execute("INSERT INTO push VALUES ('" + to + "')");
        }
        public class NotifierChain
        {
            private readonly List<INotifier> _all;
            public NotifierChain(INotifier registered) => _all = new() { registered, new SmsNotifier() };
            public void NotifyAll(string to) { foreach (var n in _all) n.Notify(to); }
        }
        public static class Registration
        {
            public static void Add(IServiceCollection services)
            {
                services.AddScoped<INotifier, EmailNotifier>();
                services.AddScoped<NotifierChain>();
            }
        }
        public class NotifyController : ControllerBase
        {
            private readonly NotifierChain _chain;
            public NotifyController(NotifierChain chain) => _chain = chain;
            public IActionResult Send(string to)
            {
                _chain.NotifyAll(to);
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_abstract_base_resolves_to_its_registered_subclass_and_the_base_body_it_inherits() => Expect("""
        public abstract class ReportBase
        {
            protected readonly SqlConnection C = new();
            public virtual void Render(string filter) => C.Execute("SELECT * FROM base WHERE " + filter); /*sink*/
            public abstract void Export(string filter);
        }
        public class SalesReport : ReportBase
        {
            public override void Export(string filter) => C.Execute("SELECT * FROM sales WHERE " + filter); /*sink*/
        }
        public class StockReport : ReportBase
        {
            public override void Render(string filter) => C.Execute("SELECT * FROM stock WHERE " + filter);
            public override void Export(string filter) => C.Execute("SELECT * FROM stock_x WHERE " + filter);
        }
        public static class Registration
        {
            public static void Add(IServiceCollection services) => services.AddScoped<ReportBase, SalesReport>();
        }
        public class ReportsController : ControllerBase
        {
            private readonly ReportBase _report;
            public ReportsController(ReportBase report) => _report = report;
            public IActionResult Show(string q)
            {
                _report.Render(q);
                _report.Export(q);
                return Ok();
            }
        }
        """);

    [Fact]
    public void Framework_built_types_are_targets_without_a_registration() => Expect("""
        public interface IJob { void Run(string arg); }
        public class SyncWorker : BackgroundService, IJob
        {
            private readonly SqlConnection _c = new();
            public void Run(string arg) => _c.Execute("INSERT INTO sync VALUES ('" + arg + "')"); /*sink*/
            protected override Task ExecuteAsync(CancellationToken ct) => Task.CompletedTask;
        }
        public class AuditFilter : Microsoft.AspNetCore.Mvc.Filters.ActionFilterAttribute, IJob
        {
            private readonly SqlConnection _c = new();
            public void Run(string arg) => _c.Execute("INSERT INTO audit VALUES ('" + arg + "')"); /*sink*/
        }
        public class SlugBinder : Microsoft.AspNetCore.Mvc.ModelBinding.IModelBinder, IJob
        {
            private readonly SqlConnection _c = new();
            public Task BindModelAsync(Microsoft.AspNetCore.Mvc.ModelBinding.ModelBindingContext context) => Task.CompletedTask;
            public void Run(string arg) => _c.Execute("INSERT INTO slug VALUES ('" + arg + "')"); /*sink*/
        }
        public class UnusedJob : IJob
        {
            private readonly SqlConnection _c = new();
            public void Run(string arg) => _c.Execute("INSERT INTO unused VALUES ('" + arg + "')");
        }
        public interface IClock { DateTime Now { get; } }
        public class SystemClock : IClock { public DateTime Now => DateTime.UtcNow; }
        public static class Registration
        {
            public static void Add(IServiceCollection services) => services.AddSingleton<IClock, SystemClock>();
        }
        public abstract class ShopController : ControllerBase
        {
            protected readonly SqlConnection C = new();
            public IActionResult Search(string q, [FromServices] IJob job, [ModelBinder(typeof(SlugBinder))] string? slug = null)
            {
                job.Run(q);
                Filter(q);
                return Ok();
            }
            protected abstract void Filter(string q);
        }
        public class ProductsController : ShopController
        {
            protected override void Filter(string q) => C.Execute("SELECT * FROM products WHERE " + q); /*sink*/
        }
        public class OrdersController : ShopController
        {
            protected override void Filter(string q) => C.Execute("SELECT * FROM orders WHERE " + q); /*sink*/
        }
        """);

    // ---- Quiet controls and fallbacks ----

    /// An interface none of whose implementations is created or registered (a registration elsewhere in the project)
    /// keeps the class hierarchy.
    [Fact]
    public void An_interface_with_no_known_implementation_keeps_the_class_hierarchy()
    {
        var code = Exporters(_ => true, "services.AddSingleton<IClock, SystemClock>();",
            "public interface IClock { DateTime Now { get; } }\npublic class SystemClock : IClock { public DateTime Now => DateTime.UtcNow; }");
        Expect(code);
        var stats = Snippet.Analyze(code).Stats;
        Assert.True(stats.DispatchByHierarchy >= 1, $"by hierarchy {stats.DispatchByHierarchy}");
        Assert.Equal(0, stats.DispatchNarrowed);
    }

    /// A solution with no registration at all (a library whose host registers it elsewhere): what source code creates is
    /// not the whole story, so the class hierarchy stays.
    [Fact]
    public void A_solution_without_any_registration_keeps_the_class_hierarchy() => Expect(Exporters(_ => true, "",
        "public static class Defaults { public static readonly IExporter Exporter = new Exporter0(); }"));

    public static IEnumerable<object[]> LibraryLoops() => new[]
    {
        new object[] { "if (type.IsSubclassOf(typeof(Stream)) && !type.IsAbstract) list.Add(Activator.CreateInstance(type, true)!);" },
        new object[] { "if (Activator.CreateInstance(type, true) is Stream stream) list.Add(stream);" },
    };

    /// Reflection over every loaded assembly filtered by a library's own base type, by `typeof` or by the type the
    /// objects are cast to (the shape of Jellyfin's subtitle formats), builds only that base type's subclasses: it opens
    /// no project, and the exporters stay narrowed.
    [Theory]
    [MemberData(nameof(LibraryLoops))]
    public void A_reflection_loop_filtered_by_a_library_type_keeps_the_narrowing(string filter) => Expect(Exporters(i => i == 3,
        "services.AddScoped<IExporter, Exporter3>();", $$"""
        public static class Streams
        {
            public static List<object> All()
            {
                var list = new List<object>();
                foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
                    foreach (var type in assembly.GetTypes())
                        {{filter}}
                return list;
            }
        }
        """));

    /// The entry reach (Task 20) follows the same targets: a heap write in an implementation nobody registers is no write
    /// of the action's request.
    [Fact]
    public void A_heap_write_in_an_unregistered_implementation_is_not_in_the_actions_reach() => Expect("""
        public static class LastSearch { public static string Term = ""; }
        public interface ISearchLog { void Remember(string term); }
        public class NullSearchLog : ISearchLog { public void Remember(string term) { } }
        public class StaticSearchLog : ISearchLog { public void Remember(string term) => LastSearch.Term = term; }
        public static class Registration
        {
            public static void Add(IServiceCollection services) => services.AddSingleton<ISearchLog, NullSearchLog>();
        }
        public class SearchController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly ISearchLog _log;
            public SearchController(ISearchLog log) => _log = log;
            public IActionResult Find(string q)
            {
                _log.Remember(q);
                _c.Execute("SELECT * FROM items WHERE name = '" + LastSearch.Term + "'");
                return Ok();
            }
        }
        """);

    public static IEnumerable<object[]> AroundConstructors() => new[]
    {
        new object[] { "", false },
        new object[] { "services.AddScoped<TenantProbe>();", true },
    };

    /// Around code (R-E16/R-E17): a constructor DI builds runs in every request. A type nobody creates or registers is
    /// never built, so its constructor is no around code; registered, it is.
    [Theory]
    [MemberData(nameof(AroundConstructors))]
    public void A_constructor_of_a_type_nobody_builds_is_no_around_code(string registration, bool found) => Expect($$"""
        public static class Tenant { public static string Name = ""; }
        public class TenantProbe
        {
            public TenantProbe(IHttpContextAccessor accessor) => Tenant.Name = accessor.HttpContext!.Request.Headers["X-Tenant"].ToString();
        }
        public static class Registration
        {
            public static void Add(IServiceCollection services)
            {
                services.AddHttpContextAccessor();
                services.AddSingleton<IClock, SystemClock>();
                {{registration}}
            }
        }
        public interface IClock { DateTime Now { get; } }
        public class SystemClock : IClock { public DateTime Now => DateTime.UtcNow; }
        public class TenantController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Show() => Ok(_c.Query<string>("SELECT * FROM t WHERE tenant = '" + Tenant.Name + "'")); {{(found ? "/*sink*/" : "")}}
        }
        """);

    // ---- Fallback scope: per project ----

    private const string Usings = """
        global using global::System;
        global using global::System.Collections.Generic;
        global using global::System.Linq;
        global using global::Microsoft.AspNetCore.Mvc;
        global using global::Microsoft.Extensions.DependencyInjection;
        global using global::Microsoft.Data.SqlClient;
        global using global::Dapper;
        """;

    private const string Contracts = """
        namespace Contracts;
        public interface IHandler { void Handle(string text); }
        """;

    private const string Plugins = """
        using Contracts;
        namespace Plugins;
        public class PluginHandler : IHandler
        {
            private readonly SqlConnection _c = new();
            public void Handle(string text) => _c.Execute("INSERT INTO plugin VALUES ('" + text + "')"); /*sink*/
        }
        """;

    private const string Core = """
        using Contracts;
        namespace Core;
        public class CoreHandler : IHandler
        {
            private readonly SqlConnection _c = new();
            public void Handle(string text) => _c.Execute("INSERT INTO core VALUES ('" + text + "')"); /*sink*/
        }
        public class SpareHandler : IHandler
        {
            private readonly SqlConnection _c = new();
            public void Handle(string text) => _c.Execute("INSERT INTO spare VALUES ('" + text + "')");
        }
        """;

    private const string Web = """
        using Contracts;
        using Scrutor;
        namespace Web;
        public static class Registration
        {
            public static void Add(IServiceCollection services)
            {
                services.AddScoped<IHandler, Core.CoreHandler>();
                SCAN
            }
        }
        public class HandleController : ControllerBase
        {
            private readonly IEnumerable<IHandler> _handlers;
            public HandleController(IEnumerable<IHandler> handlers) => _handlers = handlers;
            public IActionResult Post(string text)
            {
                foreach (var h in _handlers) h.Handle(text);
                return Ok();
            }
        }
        """;

    public static IEnumerable<object[]> ProjectScans() => new[]
    {
        new object[] { """
            foreach (var type in typeof(Plugins.PluginHandler).Assembly.GetTypes())
                        if (type.IsClass && !type.IsAbstract) services.AddScoped(typeof(IHandler), type);
            """ },
        new object[] { "services.Scan(s => s.FromAssemblyOf<Plugins.PluginHandler>().AddClasses().AsImplementedInterfaces());" },
        new object[] { """
            var plugins = typeof(Plugins.PluginHandler).Assembly;
                    foreach (var type in plugins.GetTypes()) services.AddScoped(typeof(IHandler), type);
            """ },
    };

    /// A scan of one project's assembly (a `GetTypes()` loop, Scrutor's `FromAssemblyOf<T>()`) opens that project only:
    /// every handler of the scanned Plugins project is a target, Core's registered handler too, and Core's spare handler,
    /// which nobody registers, is not.
    [Theory]
    [MemberData(nameof(ProjectScans))]
    public void A_scan_of_one_projects_assembly_opens_that_project_only(string scan)
    {
        var dir = TempDir();
        var references = FixtureReferences.All.Select(r => ((PortableExecutableReference)r).FilePath!).ToList();
        var usings = Path.Combine(dir, "GlobalUsings.g.cs");
        File.WriteAllText(usings, Usings);
        CompilationInput Project(string name, string code, params string[] refs)
        {
            var projectDir = Path.Combine(dir, name);
            Directory.CreateDirectory(projectDir);
            var source = Path.Combine(projectDir, name + ".cs");
            File.WriteAllText(source, code);
            return new CompilationInput(
                Path.Combine(projectDir, name + ".csproj"), "net8.0", name, OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12,
                NullableContextOptions.Enable, Array.Empty<string>(), false, null, new[] { source, usings }, references,
                refs.Select(r => Path.Combine(dir, r, r + ".csproj")).ToList(), Path.Combine(dir, name + ".txt"));
        }
        var inputs = new[]
        {
            Project("Web", Web.Replace("SCAN", scan, StringComparison.Ordinal), "Contracts", "Core", "Plugins", "Scrutor"),
            Project("Scrutor", ScrutorShim),
            Project("Core", Core, "Contracts"),
            Project("Plugins", Plugins, "Contracts"),
            Project("Contracts", Contracts),
        };
        var solution = SolutionLoader.Load(inputs, CancellationToken.None);
        Assert.All(solution.Projects, p => Assert.Empty(p.Errors));
        var result = new TaintEngine(Snippet.Models, Snippet.Options).Analyze(solution, CancellationToken.None);
        var found = result.Findings.Select(f => (Path.GetFileName(f.Sink.SourceTree!.FilePath), f.Sink.GetLineSpan().StartLinePosition.Line + 1))
            .OrderBy(x => x).ToList();
        var expected = new[] { ("Core.cs", Snippet.Marked(Core).Single()), ("Plugins.cs", Snippet.Marked(Plugins).Single()) }.ToList();
        Assert.Equal(expected, found);
        Assert.Equal(1, result.Stats.OpenProjects);
    }
}
