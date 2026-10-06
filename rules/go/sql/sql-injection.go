package shop

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"example.com/shop/models"
)

type Handler struct {
	db *sql.DB
}

func (h *Handler) Orders(w http.ResponseWriter, r *http.Request) {
	customer := r.URL.Query().Get("customer")
	// ruleid: go.sql-injection
	rows, _ := h.db.Query("SELECT * FROM orders WHERE customer = '" + customer + "'")
	defer rows.Close()
	// ruleid: go.sql-injection
	h.db.QueryRow(fmt.Sprintf("SELECT * FROM orders WHERE id = %s", r.FormValue("id")))
	query := "DELETE FROM orders WHERE note = '" + r.PostFormValue("note") + "'"
	// ruleid: go.sql-injection
	h.db.Exec(query)
	// ruleid: go.sql-injection
	h.db.QueryContext(r.Context(), "SELECT * FROM items WHERE sku = '"+r.Header.Get("X-Sku")+"'")
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM orders WHERE customer = ?", customer)
	// ok: go.sql-injection
	h.db.QueryContext(r.Context(), "SELECT * FROM orders WHERE id = $1", r.FormValue("id"))
	// ok: go.sql-injection
	h.db.Exec("DELETE FROM orders WHERE expired")
	column := "name"
	if r.FormValue("sort") == "price" {
		column = "price"
	}
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items ORDER BY " + column)
	id, _ := strconv.Atoi(r.FormValue("id"))
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM items WHERE id = %d", id))
	fmt.Fprintln(w, "ok")
}

// net/http (Go 1.22 ServeMux patterns): r.PathValue, and transactions and prepared statements.
func (h *Handler) Order(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.sql-injection
	h.db.QueryRow("SELECT * FROM orders WHERE id = " + r.PathValue("id"))
	// ok: go.sql-injection
	h.db.QueryRow("SELECT * FROM orders WHERE id = $1", r.PathValue("id"))
	tx, _ := h.db.Begin()
	// ruleid: go.sql-injection
	tx.Exec("UPDATE orders SET note = '" + r.URL.Query().Get("note") + "'")
	// ok: go.sql-injection
	tx.Exec("UPDATE orders SET note = ? WHERE id = ?", r.URL.Query().Get("note"), r.PathValue("id"))
	stmt, _ := h.db.Prepare("SELECT * FROM orders WHERE id = ?")
	// ok: go.sql-injection
	stmt.Query(r.PathValue("id"))
	conn, _ := h.db.Conn(r.Context())
	// ruleid: go.sql-injection
	conn.ExecContext(r.Context(), "DELETE FROM orders WHERE id = "+r.PathValue("id"))
	fmt.Fprintln(w, "ok")
}

// Routers on net/http: chi and gorilla/mux route variables.
func (h *Handler) Article(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM articles WHERE slug = '" + chi.URLParam(r, "slug") + "'")
	vars := mux.Vars(r)
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM articles WHERE category = '" + vars["category"] + "'")
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM articles WHERE slug = ? AND category = ?", chi.URLParam(r, "slug"), vars["category"])
	fmt.Fprintln(w, "ok")
}

// Gin: path parameters, query strings, forms and headers on *gin.Context.
func (h *Handler) GinItem(c *gin.Context) {
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE id = '" + c.Param("id") + "'")
	// ruleid: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM items WHERE name = '%s'", c.Query("name")))
	// ruleid: go.sql-injection
	h.db.Exec("UPDATE items SET note = '" + c.PostForm("note") + "'")
	// ruleid: go.sql-injection
	h.db.Exec("INSERT INTO log (agent) VALUES ('" + c.GetHeader("User-Agent") + "')")
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE sku = '" + c.Request.URL.Query().Get("sku") + "'")
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE id = ? AND name = ?", c.Param("id"), c.DefaultQuery("name", ""))
	// ok: go.sql-injection
	h.db.QueryContext(c.Request.Context(), "SELECT * FROM items WHERE id = ?", c.Param("id"))
	c.String(http.StatusOK, "ok")
}

// Echo: path parameters, query parameters and form values on echo.Context.
func (h *Handler) EchoItem(c echo.Context) error {
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE id = '" + c.Param("id") + "'")
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + c.QueryParam("name") + "'")
	// ruleid: go.sql-injection
	h.db.Exec("UPDATE items SET note = '" + c.FormValue("note") + "'")
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE sku = '" + c.Request().URL.Query().Get("sku") + "'")
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE id = ? AND name = ?", c.Param("id"), c.QueryParam("name"))
	return c.String(http.StatusOK, "ok")
}

// GORM: conditions with placeholders, structs and maps bind their values; the methods the GORM
// security guide names take SQL text.
type Item struct {
	ID   uint
	Name string
}

type Store struct {
	gdb *gorm.DB
	xdb *sqlx.DB
}

func (s *Store) Items(c *gin.Context) {
	var item Item
	var items []Item
	// ok: go.sql-injection
	s.gdb.Where("name = ?", c.Query("name")).First(&item)
	// ok: go.sql-injection
	s.gdb.First(&item, "id = ?", c.Param("id"))
	// ok: go.sql-injection
	s.gdb.Where(&Item{Name: c.Query("name")}).Find(&items)
	// ok: go.sql-injection
	s.gdb.Where(map[string]interface{}{"name": c.Query("name")}).Find(&items)
	// ok: go.sql-injection
	s.gdb.Raw("SELECT * FROM items WHERE name = ?", c.Query("name")).Scan(&item)
	// ok: go.sql-injection
	s.gdb.Exec("UPDATE items SET name = ? WHERE id = ?", c.PostForm("name"), c.Param("id"))
	// ruleid: go.sql-injection
	s.gdb.Raw("SELECT * FROM items WHERE name = '" + c.Query("name") + "'").Scan(&item)
	// ruleid: go.sql-injection
	s.gdb.Where(fmt.Sprintf("name = '%s'", c.Query("name"))).First(&item)
	// ruleid: go.sql-injection
	s.gdb.Exec("DELETE FROM items WHERE name = '" + c.PostForm("name") + "'")
	// ruleid: go.sql-injection
	s.gdb.Order(c.Query("sort")).Find(&items)
	// ruleid: go.sql-injection
	s.gdb.First(&item, c.Param("id"))
	// ruleid: go.sql-injection
	s.gdb.Where("deleted_at IS NULL").Where("name = '" + c.Query("name") + "'").Find(&items)
	id, _ := strconv.Atoi(c.Param("id"))
	// ok: go.sql-injection
	s.gdb.First(&item, id)
	// sqlx is not followed yet.
	// todoruleid: go.sql-injection
	s.xdb.Select(&items, "SELECT * FROM items WHERE name = '"+c.Query("name")+"'")
	c.JSON(http.StatusOK, items)
}

// Request bodies decoded or bound into a struct: encoding/json, Gin and Echo binding.
type ItemInput struct {
	Name string `json:"name"`
}

func (h *Handler) CreateItem(w http.ResponseWriter, r *http.Request) {
	var in ItemInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return
	}
	// ruleid: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES ('" + in.Name + "')")
	// ok: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES (?)", in.Name)
	body, _ := io.ReadAll(r.Body)
	var other ItemInput
	json.Unmarshal(body, &other)
	// ruleid: go.sql-injection
	h.db.Exec("DELETE FROM items WHERE name = '" + other.Name + "'")
	fmt.Fprintln(w, "ok")
}

func (h *Handler) GinCreateItem(c *gin.Context) {
	var in ItemInput
	if err := c.ShouldBindJSON(&in); err != nil {
		return
	}
	// ruleid: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES ('" + in.Name + "')")
	// ok: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES (?)", in.Name)
	var query ItemInput
	c.BindQuery(&query)
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + query.Name + "'")
}

func (h *Handler) EchoCreateItem(c echo.Context) error {
	var in ItemInput
	if err := c.Bind(&in); err != nil {
		return err
	}
	// ruleid: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES ('" + in.Name + "')")
	var body ItemInput
	if err := echo.BindBody(c, &body); err != nil {
		return err
	}
	// ruleid: go.sql-injection
	h.db.Exec("UPDATE items SET name = '" + body.Name + "'")
	// ok: go.sql-injection
	h.db.Exec("UPDATE items SET name = ?", body.Name)
	return nil
}

// Echo's DefaultBinder used directly: its BindBody, BindQueryParams, BindPathParams and
// BindHeaders methods, and Bind (v4 argument order: target first).
type ItemFilter struct {
	Name  string `query:"name"`
	Slug  string `param:"slug"`
	Agent string `header:"User-Agent"`
}

func (h *Handler) EchoBinderItems(c echo.Context) error {
	var body ItemInput
	if err := (&echo.DefaultBinder{}).BindBody(c, &body); err != nil {
		return err
	}
	// ruleid: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES ('" + body.Name + "')")
	// ok: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES (?)", body.Name)
	binder := new(echo.DefaultBinder)
	var filter ItemFilter
	if err := binder.BindQueryParams(c, &filter); err != nil {
		return err
	}
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + filter.Name + "'")
	var route ItemFilter
	binder.BindPathParams(c, &route)
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE slug = '" + route.Slug + "'")
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE slug = ?", route.Slug)
	hb := &echo.DefaultBinder{}
	var headers ItemFilter
	hb.BindHeaders(c, &headers)
	// ruleid: go.sql-injection
	h.db.Exec("INSERT INTO log (agent) VALUES ('" + headers.Agent + "')")
	var all ItemFilter
	binder.Bind(&all, c)
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + all.Name + "'")
	var fixed ItemFilter
	fixed.Name = "default"
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + fixed.Name + "'")
	return nil
}

// OpenGrep 1.30.0 gives the field h.db the type of a local variable with the same name, so the
// typed *sql.DB receiver no longer matches.
func (h *Handler) ShadowedField(c echo.Context) error {
	db := &echo.DefaultBinder{}
	var filter ItemFilter
	db.BindQueryParams(c, &filter)
	// todoruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + filter.Name + "'")
	return nil
}

// Bind targets made with new(T) or &T{} and passed without `&`.
func (h *Handler) EchoNewTargets(c echo.Context) error {
	u := new(ItemInput)
	if err := c.Bind(u); err != nil {
		return err
	}
	// ruleid: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES ('" + u.Name + "')")
	// ok: go.sql-injection
	h.db.Exec("INSERT INTO items (name) VALUES (?)", u.Name)
	filter := &ItemFilter{}
	(&echo.DefaultBinder{}).BindQueryParams(c, filter)
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + filter.Name + "'")
	binder := new(echo.DefaultBinder)
	route := new(ItemFilter)
	binder.BindPathParams(c, route)
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE slug = '" + route.Slug + "'")
	all := new(ItemFilter)
	binder.Bind(all, c)
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + all.Name + "'")
	headers := new(ItemFilter)
	echo.BindHeaders(c, headers)
	// ruleid: go.sql-injection
	h.db.Exec("INSERT INTO log (agent) VALUES ('" + headers.Agent + "')")
	preset := new(ItemFilter)
	preset.Name = "featured"
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + preset.Name + "'")
	// The binder of the Echo instance (an echo.Binder interface) is not followed.
	var viaEcho ItemFilter
	c.Echo().Binder.Bind(&viaEcho, c)
	// todoruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + viaEcho.Name + "'")
	return nil
}

func (h *Handler) GinNewTargets(c *gin.Context) {
	in := new(ItemInput)
	if err := c.ShouldBindJSON(in); err != nil {
		return
	}
	// ruleid: go.sql-injection
	h.db.Exec("UPDATE items SET name = '" + in.Name + "'")
	query := &ItemInput{}
	c.ShouldBindQuery(query)
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + query.Name + "'")
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = ?", query.Name)
}

// A bind or decode call inside a condition (`if c.ShouldBindJSON(&in) == nil`) fills the struct
// with request data like the `err :=` form. A bound value used only in a comparison does not
// taint what the branch chooses.
type SortInput struct {
	Name string   `json:"name" query:"name"`
	Sort string   `json:"sort" query:"sort"`
	Tags []string `json:"tags" query:"tags"`
}

func (h *Handler) GinBindInCondition(c *gin.Context) {
	var in SortInput
	if c.ShouldBindJSON(&in) == nil {
		// ruleid: go.sql-injection
		h.db.Query("SELECT * FROM items WHERE name = '" + in.Name + "'")
	}
	var query SortInput
	if c.ShouldBindQuery(&query) != nil {
		return
	}
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items ORDER BY " + query.Sort)
	target := new(SortInput)
	if c.ShouldBind(target) == nil && target.Sort != "" {
		// ruleid: go.sql-injection
		h.db.Query("SELECT * FROM items ORDER BY " + target.Sort)
	}
	var strict SortInput
	if errors.Is(c.ShouldBindJSON(&strict), io.EOF) {
		return
	}
	// ruleid: go.sql-injection
	h.db.Exec("DELETE FROM items WHERE name = '" + strict.Name + "'")
	var empty SortInput
	if c.ShouldBindJSON(&empty) == io.EOF {
		return
	}
	// ruleid: go.sql-injection
	h.db.Exec("DELETE FROM items WHERE name = '" + empty.Name + "'")
	// The bound values only compared: the branches choose constants.
	column := "name"
	if query.Sort == "price" {
		column = "price"
	}
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items ORDER BY " + column)
	descending := in.Sort == "desc" && in.Name != ""
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM items ORDER BY id %s", map[bool]string{true: "DESC", false: "ASC"}[descending]))
	tagged := in.Tags != nil
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM items WHERE tagged = %t", tagged))
	switch query.Sort {
	case "price":
		// ok: go.sql-injection
		h.db.Query("SELECT * FROM items ORDER BY price")
	}
	// Other comparisons with nil, and calls that fill a variable, stay booleans.
	multi := c.QueryArray("color") != nil
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM items WHERE colored = %t", multi))
	var stock int
	known := h.db.QueryRow("SELECT stock FROM items WHERE name = ?", c.Query("item")).Scan(&stock) == nil
	// ok: go.sql-injection
	h.db.Exec(fmt.Sprintf("UPDATE lookups SET found = %t", known))
	// The success flag of a bind call is reported: the comparison holds the bind call, and
	// the call's result counts as request data.
	var draft SortInput
	parsed := c.ShouldBindJSON(&draft) == nil
	// todook: go.sql-injection
	h.db.Exec(fmt.Sprintf("UPDATE drafts SET valid = %t", parsed))
}

func (h *Handler) EchoBindInCondition(c echo.Context) error {
	var in SortInput
	if c.Bind(&in) != nil {
		return nil
	}
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + in.Name + "'")
	var filter SortInput
	if echo.BindQueryParams(c, &filter) == nil {
		// ruleid: go.sql-injection
		h.db.Query("SELECT * FROM items ORDER BY " + filter.Sort)
	}
	order := "id"
	if filter.Sort == "name" {
		order = "name"
	}
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM items ORDER BY " + order)
	return nil
}

func (h *Handler) DecodeInCondition(w http.ResponseWriter, r *http.Request) {
	var in SortInput
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		return
	}
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM items WHERE name = '" + in.Name + "'")
	tagged := in.Name == "featured"
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM items WHERE featured = %t", tagged))
}

// A binder held in a struct field, typed as *echo.DefaultBinder.
type EchoAPI struct {
	db     *sql.DB
	binder *echo.DefaultBinder
	saved  *SavedFilters
}

// SavedFilters fills a filter from server-side presets, not from the request.
type SavedFilters struct{}

func (s *SavedFilters) BindQueryParams(c echo.Context, f *ItemFilter) error {
	f.Name = "featured"
	return nil
}

func (a *EchoAPI) Search(c echo.Context) error {
	var filter ItemFilter
	if err := a.binder.BindQueryParams(c, &filter); err != nil {
		return err
	}
	// ruleid: go.sql-injection
	a.db.Query("SELECT * FROM items WHERE name = '" + filter.Name + "'")
	// ok: go.sql-injection
	a.db.Query("SELECT * FROM items WHERE name = ?", filter.Name)
	var preset ItemFilter
	a.saved.BindQueryParams(c, &preset)
	// ok: go.sql-injection
	a.db.Query("SELECT * FROM items WHERE name = '" + preset.Name + "'")
	return nil
}

// GORM handles derived from a *gorm.DB (WithContext, Session, Debug, a transaction).
func (s *Store) Scoped(c *gin.Context) {
	var items []Item
	db := s.gdb.WithContext(c.Request.Context())
	// ruleid: go.sql-injection
	db.Where("name = '" + c.Query("name") + "'").Find(&items)
	// ok: go.sql-injection
	db.Where("name = ?", c.Query("name")).Find(&items)
	sess := s.gdb.Session(&gorm.Session{PrepareStmt: true})
	// ruleid: go.sql-injection
	sess.Order(c.Query("sort")).Find(&items)
	dbg := s.gdb.Debug()
	// ruleid: go.sql-injection
	dbg.Raw("SELECT * FROM items WHERE name = '" + c.Query("name") + "'").Scan(&items)
	tx := s.gdb.Begin()
	// ruleid: go.sql-injection
	tx.Exec("DELETE FROM items WHERE name = '" + c.Query("name") + "'")
	// ok: go.sql-injection
	tx.Exec("DELETE FROM items WHERE name = ?", c.Query("name"))
	tx.Commit()
	c.JSON(http.StatusOK, items)
}

// Numeric and boolean fields of a bound struct cannot carry SQL text: the decoder or binder has
// already parsed them into numbers. Its string fields stay tainted.
type OrderInput struct {
	Customer string  `json:"customer" form:"customer" query:"customer"`
	ID       int     `json:"id" form:"id" query:"id"`
	Page     int64   `json:"page" form:"page" query:"page"`
	Limit    uint32  `json:"limit" form:"limit" query:"limit"`
	MinTotal float64 `json:"min_total" form:"min_total" query:"min_total"`
	Paid     bool    `json:"paid" form:"paid" query:"paid"`
	Status   Status  `json:"status" form:"status" query:"status"`
}

// Status is a named numeric type.
type Status int

func (h *Handler) NumericOrders(w http.ResponseWriter, r *http.Request) {
	var in OrderInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return
	}
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders WHERE id = %d", in.ID))
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders WHERE total >= %f AND paid = %t", in.MinTotal, in.Paid))
	// ok: go.sql-injection
	h.db.Query("SELECT * FROM orders LIMIT " + strconv.FormatUint(uint64(in.Limit), 10))
	// ruleid: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders WHERE id = %d AND customer = '%s'", in.ID, in.Customer))
	body, _ := io.ReadAll(r.Body)
	var other OrderInput
	json.Unmarshal(body, &other)
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders OFFSET %d", other.Page*20))
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM orders WHERE customer = '" + other.Customer + "'")
	// A struct declared in another package: its field types are not known here, so the whole
	// struct stays tainted.
	var ext models.Order
	json.NewDecoder(r.Body).Decode(&ext)
	// todook: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders WHERE quantity = %d", ext.Quantity))
	// OpenGrep 1.30.0 gives a field of such a struct the type of a same-named field of a struct
	// declared here (OrderInput.ID is an int), so a string field called ID counts as a number.
	// todoruleid: go.sql-injection
	h.db.Query("SELECT * FROM orders WHERE ref = '" + ext.ID + "'")
	fmt.Fprintln(w, "ok")
}

func (h *Handler) GinNumericOrders(c *gin.Context) {
	var in OrderInput
	if err := c.ShouldBindQuery(&in); err != nil {
		return
	}
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders LIMIT %d OFFSET %d", in.Limit, in.Page))
	// ruleid: go.sql-injection
	h.db.Query("SELECT * FROM orders WHERE customer = '" + in.Customer + "'")
	var form OrderInput
	c.ShouldBind(&form)
	// ok: go.sql-injection
	h.db.Exec("DELETE FROM orders WHERE id = " + strconv.Itoa(form.ID))
}

func (h *Handler) EchoNumericOrders(c echo.Context) error {
	var in OrderInput
	if err := c.Bind(&in); err != nil {
		return err
	}
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders WHERE id = %d", in.ID))
	// ruleid: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders WHERE customer = '%s'", in.Customer))
	// A number turned back into a character (string(rune(n)), %c) can be a quote; the numeric
	// field already counts as clean, so this is missed.
	// todoruleid: go.sql-injection
	h.db.Query("SELECT * FROM orders WHERE grade = '" + string(rune(in.ID)) + "'")
	var q OrderInput
	echo.BindQueryParams(c, &q)
	// ok: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders LIMIT %d", q.Limit))
	// A named numeric type is not in the list of clean types, so it stays tainted.
	// todook: go.sql-injection
	h.db.Query(fmt.Sprintf("SELECT * FROM orders WHERE status = %d", q.Status))
	return nil
}
