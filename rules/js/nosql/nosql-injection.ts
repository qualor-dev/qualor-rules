import express, { Request, Response } from 'express';
import { MongoClient } from 'mongodb';
import mongoose from 'mongoose';
import type { NextRequest } from 'next/server';
import Fastify from 'fastify';
import Post from '@/models/Post';

const client = new MongoClient('mongodb://localhost:27017');
const posts = client.db('blog').collection('posts');
const app = express();

// TypeScript: typed Express handlers.
app.post('/posts/claim', async (req: Request, res: Response) => {
  // ruleid: js.nosql-injection
  const post = await posts.findOneAndUpdate({ claimCode: req.body.code }, { $set: { claimed: true } });
  // ok: js.nosql-injection
  await posts.findOne({ claimCode: String(req.body.code) });
  res.json(post);
});

// Express 5 parses query strings with the simple parser by default: its values are strings or
// arrays, which cannot carry operators. The rule does not know the parser and reports them.
app.set('query parser', 'simple');
app.get('/posts', async (req: Request, res: Response) => {
  // todook: js.nosql-injection
  const list = await posts.find({ tag: req.query.tag }).toArray();
  res.json(list);
});

// Next.js App Router route handlers: the JSON body can carry operators, the URL parameters and
// the route segments are strings.
export async function POST(request: NextRequest) {
  const body = await request.json();
  // ruleid: js.nosql-injection
  const found = await posts.findOne({ author: body.author, secret: body.secret });
  // ruleid: js.nosql-injection
  await Post.deleteMany({ author: body.author });
  // A field value that is not a variable or a property chain is not followed.
  // todoruleid: js.nosql-injection
  await Post.deleteMany({ author: (await request.json()).author });
  // ok: js.nosql-injection
  await posts.findOne({ author: { $eq: body.author } });
  return Response.json(found);
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const tag = request.nextUrl.searchParams.get('tag');
  // ok: js.nosql-injection
  const post = await posts.findOne({ slug, tag });
  // ruleid: js.nosql-injection
  await posts.find({ $where: 'this.slug == "' + slug + '"' }).toArray();
  // ruleid: js.nosql-injection
  await posts.find({ $where: `this.tag == '${tag}'` }).toArray();
  return Response.json(post);
}

// A helper with a request-like parameter that is not a route handler.
export async function findPost(request: { author: string }) {
  // ok: js.nosql-injection
  return posts.findOne({ author: request.author });
}

// Fastify with TypeScript route generics.
const server = Fastify();

server.post<{ Body: { owner: string } }>('/posts/owned', async (request) => {
  // ruleid: js.nosql-injection
  return Post.find({ owner: request.body.owner });
});

// Mongoose with sanitizeFilter switched on for every query of this file.
mongoose.set('sanitizeFilter', true);

app.post('/posts/mine', async (req: Request, res: Response) => {
  // ok: js.nosql-injection
  res.json(await Post.find({ owner: req.body.owner }));
});

export default app;
