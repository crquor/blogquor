import sqlite3

def nest_comments(post_id):
    with sqlite3.connect("app.db") as con:
        con.row_factory = sqlite3.Row
        cursor = con.cursor()

        # Get all the comments associated with the post, sorted by the latest date
        comments = cursor.execute(
            """
            SELECT * FROM comments 
            WHERE post_id = ? 
            ORDER BY TIMESTAMP DESC;
            """,
            (post_id,),
        ).fetchall()

        # Convert sqlite3.Row objects to dictionaries
        comments = [dict(c) for c in comments]

        # Create a dictionary where the key is the id of each comment and the value is the comment itself
        comment_map = {}
        for c in comments:
            # Ensure each comment has a "replies" key
            c["replies"] = []
            comment_map[c["id"]] = c

        # Nest replies under their parent comments
        for c in comments:
            if c["parent_id"]:
                if c["parent_id"] in comment_map:
                    # Add the current comment as a reply to its parent
                    comment_map[c["parent_id"]]["replies"].append(c)
                else:
                    print(
                        f"Warning: Parent comment {c['parent_id']} not found for comment {c['id']}."
                    )

        # Return only top-level comments (those with no parent_id)
        return [c for c in comments if c["parent_id"] is None]
