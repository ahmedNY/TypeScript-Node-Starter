import { Request, Response } from "express";
import { getManager } from "typeorm";
import { Post } from "../models/Post";

/**
 * Loads all posts from the database.
 */
export let postGetAllAction = async (req: Request, res: Response) => {

    // get a post repository to perform operations with post
    const postRepository = getManager().getRepository(Post);

    // load a post by a given post id
    const posts = await postRepository.find();

    // return loaded posts
    res.send(posts);
};

/**
 * Loads post by a given id.
 */
export let postGetByIdAction = async (req: Request, res: Response) => {

    // get a post repository to perform operations with post
    const postRepository = getManager().getRepository(Post);

    // load a post by a given post id
    const post = await postRepository.findOneById(req.params.id);

    // if post was not found return 404 to the client
    if (!post) {
        res.status(404);
        res.end();
        return;
    }

    // return loaded post
    res.send(post);
};


/**
 * Saves given post.
 */
export let postSaveAction = async (req: Request, res: Response) => {

    // get a post repository to perform operations with post
    const postRepository = getManager().getRepository(Post);

    // create a real post object from post json object sent over http
    const newPost = postRepository.create(req.body);

    // save received post
    await postRepository.save(newPost);

    // return saved post back
    res.send(newPost);
};
