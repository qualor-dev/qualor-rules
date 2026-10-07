import { Controller, Get, Param } from '@nestjs/common';
import type { NextRequest } from 'next/server';
import Fastify, { FastifyRequest } from 'fastify';
import { headers } from 'next/headers';
import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import { DataSource } from 'typeorm';

const app = express();
const pool = new Pool();
const dataSource = new DataSource({ type: 'postgres' });

// TypeScript: typed Express handlers.
app.get('/accounts/:id', async (req: Request, res: Response) => {
  // ruleid: js.sql-injection
  const found = await pool.query(`SELECT * FROM accounts WHERE id = '${req.params.id}'`);
  // ok: js.sql-injection
  const bound = await pool.query('SELECT * FROM accounts WHERE id = $1', [req.params.id]);
  res.json({ found: found.rows, bound: bound.rows });
});

// TypeORM: DataSource.query with parameters, and the query builder with named parameters.
app.get('/members', async (req: Request, res: Response) => {
  const name = String(req.query.name);
  // ok: js.sql-injection
  await dataSource.query('SELECT * FROM members WHERE name = $1', [name]);
  // ok: js.sql-injection
  await dataSource.createQueryBuilder().select('m').from('members', 'm').where('m.name = :name', { name }).getMany();
  // ruleid: js.sql-injection
  await dataSource.query("SELECT * FROM members WHERE name = '" + name + "'");
  res.end();
});

// NestJS: parameters bound with @Param()/@Query()/@Body() are not sources yet.
@Controller('cats')
export class CatsController {
  @Get(':id')
  async findOne(@Param('id') id: string) {
    // todoruleid: js.sql-injection
    return pool.query("SELECT * FROM cats WHERE id = '" + id + "'");
  }
}

// Next.js App Router route handlers (app/**/route.ts): the request, and the dynamic segments in
// the context's params.
export async function PUT(request: NextRequest, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  // ruleid: js.sql-injection
  await pool.query(`UPDATE posts SET views = views + 1 WHERE slug = '${slug}'`);
  // ok: js.sql-injection
  await pool.query('UPDATE posts SET views = views + 1 WHERE slug = $1', [slug]);
  return Response.json({});
}

export async function PATCH(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  // ruleid: js.sql-injection
  await pool.query("UPDATE posts SET draft = false WHERE id = '" + id + "'");
  return Response.json({ id });
}

export async function POST(request: Request) {
  const body = await request.json();
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO posts (title) VALUES ('" + body.title + "')");
  const form = await request.formData();
  // ruleid: js.sql-injection
  await pool.query(`INSERT INTO posts (author) VALUES ('${form.get('author')}')`);
  // ok: js.sql-injection
  await pool.query('INSERT INTO posts (title) VALUES ($1)', [body.title]);
  return Response.json({});
}

export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const tag = searchParams.get('tag');
  // ruleid: js.sql-injection
  await pool.query("DELETE FROM posts WHERE tag = '" + tag + "'");
  // ruleid: js.sql-injection
  await pool.query("DELETE FROM sessions WHERE token = '" + request.cookies.get('token')?.value + "'");
  // ok: js.sql-injection
  await pool.query('DELETE FROM posts WHERE tag = $1', [tag]);
  // ok: js.sql-injection
  await pool.query('DELETE FROM posts WHERE id = ' + Number(searchParams.get('id')));
  return new Response(null, { status: 204 });
}

export const HEAD = async (request: NextRequest) => {
  // ruleid: js.sql-injection
  await pool.query("SELECT 1 FROM posts WHERE slug = '" + request.nextUrl.pathname + "'");
  return new Response(null);
};

export async function OPTIONS() {
  // ok: js.sql-injection
  await pool.query("SELECT 1 FROM posts WHERE kind = 'public'");
  return new Response(null);
}

// Request headers read through next/headers (also in Server Components): not a source yet.
export async function GETAgent() {
  const agent = (await headers()).get('user-agent');
  // todoruleid: js.sql-injection
  await pool.query("INSERT INTO agents (name) VALUES ('" + agent + "')");
  return Response.json({});
}

// A helper with a request-like parameter that is not a route handler.
export async function loadPost(request: { slug: string }) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM posts WHERE slug = '" + request.slug + "'");
}

// Fastify with TypeScript route generics.
const server = Fastify();

server.get<{ Querystring: { q: string } }>('/search', async (request) => {
  // ruleid: js.sql-injection
  return pool.query("SELECT * FROM posts WHERE title LIKE '%" + request.query.q + "%'");
});

// Typed handlers that destructure the request or the context.
app.get('/books', async ({ query }: Request, res: Response) => {
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM books WHERE title = '" + query.title + "'");
  res.end();
});

app.get('/books/:id', async ({ params: { id } }: Request<{ id: string }>, res: Response) => {
  // ruleid: js.sql-injection
  await pool.query(`SELECT * FROM books WHERE id = '${id}'`);
  // ok: js.sql-injection
  await pool.query('SELECT * FROM books WHERE id = $1', [id]);
  res.end();
});

server.get('/tags', async ({ query }: FastifyRequest<{ Querystring: { q: string } }>) => {
  // ruleid: js.sql-injection
  return pool.query("SELECT * FROM tags WHERE name = '" + query.q + "'");
});

export async function GET({ nextUrl }: NextRequest, { params: { slug } }: { params: { slug: string } }) {
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM posts WHERE slug = '" + slug + "'");
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM posts WHERE tag = '" + nextUrl.searchParams.get('tag') + "'");
  // ok: js.sql-injection
  await pool.query('SELECT * FROM posts WHERE slug = $1', [slug]);
  return Response.json({});
}

// A function that is not named after an HTTP method is no route handler.
export async function preview({ url }: NextRequest) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM previews WHERE url = '" + url + "'");
}

export default app;
