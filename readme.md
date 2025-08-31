# dorbs

**dorbs** (short for "adorable server") is a tiny web server with strict limitations added for for potential security and performance:

- Serves **only** `.html`, `.css`, `.js`, `.glb`, `.svg`, `.ico`, `.rss`, `.woff2`, and `.webp` files
- Files are served **only** from the executable's folder, no subfolders

Security and performance are very much just potential, though, since the whole thing's vibe coded.

So, you know, don't use it  ¯\\\_(ツ)\_/¯

The executable ("dorbs") is all you need, use it (you really shouldn't!) by writing ./dorbs, or ./dorbs [port number] – the port number defaults to 9001

"dorbs.c" contains the source code, "Makefile" is the makefile and the rest is just an example for seeing if the server is running and serving files properly.

All emotes have been grabbed from https://emotes.io/, some have been slightly modified.

suzanne.glb is the head of the blender mascot, read more about her and other mesh primitives here: https://docs.blender.org/manual/en/latest/modeling/meshes/primitives.html