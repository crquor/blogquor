import sqlite3
import logging
import os
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash,
    send_from_directory,
    jsonify,
)
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from bleach import clean
from bleach.css_sanitizer import CSSSanitizer
from flask_xcaptcha import XCaptcha
from helpers import login_required, validate_email, ispwd_strong
from commentsystem import nest_comments

# Setup the flask app
app = Flask(__name__)

# Setup the session for user authentication functionality
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# set up logging
logging.basicConfig(level=logging.ERROR)


# Configure xcaptcha for hcaptcha

app.config["XCAPTCHA_SITE_KEY"] = "258ea2f2-7f5e-46be-9642-8838e024875c"
app.config["XCAPTCHA_SECRET_KEY"] = "ES_f8e8f86f3f9b48318afc45a40471163e"
app.config["XCAPTCHA_VERIFY_URL"] = "https://api.hcaptcha.com/siteverify"
app.config["XCAPTCHA_API_URL"] = "https://hcaptcha.com/1/api.js"
app.config["XCAPTCHA_DIV_CLASS"] = "h-captcha"
app.config["XCAPTCHA_THEME"] = "dark"

xcaptcha = XCaptcha(app=app)


# Setup bleach

bleach_tags = [
    "p",
    "strong",
    "em",
    "u",
    "a",
    "ul",
    "ol",
    "li",
    "br",
    "h1",
    "h2",
    "h3",
    "h4",
    "span",
    "blockquote",
    "code",
    "pre",
    "div",
    "s",
]

bleach_attributes = ["href", "target", "style", "class", "spell-check", "data-language"]

bleach_css_sanitizer = CSSSanitizer(
    allowed_css_properties=[
        "color",
        "font-weight",
        "background-color",
        "font-size",
        "font-family",
        "text-align",
        "text-decoration"
    ]
)


# Route for homepage


@app.route("/", methods=["GET"])
def main():

    try:
        # Connect to the database and access the data by rows using row_factory object
        with sqlite3.connect("app.db") as con:

            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            # Select latest posts to display it in the home page
            posts = cursor.execute("SELECT * FROM posts ORDER BY created_at DESC;").fetchall()

            # Select 25 of the tags to allow users to filter posts by tag from the home page
            tags = cursor.execute("SELECT * FROM tags LIMIT 25;").fetchall()

            # Render the data to the user
            return render_template("index.html", posts=posts, tags=tags)

    # In case of database error, display an error page
    except sqlite3.Error as e:
        logging.error(f"sqlite3 Error: {e}")
        return render_template(
            "error.html", rtnvalue="Something went wrong on our side"
        )


# Route to serve files from the uploads/images folder


@app.route("/uploads/images/<filename>")
def uploaded_file(filename):
    return send_from_directory("uploads/images", filename)


# Route for allowing user to search the posts by title


@app.route("/search")
def search():

    # Display the template which has searchbox
    return render_template("search.html")


# Route for displaying search results related to the title


@app.route("/searchResults", methods=["POST"])
def search_results():

    # Get the input from the user
    data = request.get_json()
    query = data.get("q", "").lower()

    try:
        # Connect to the database and access the data by rows using row_factory object
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            searchData = cursor.execute(
                "SELECT id,title,created_at,post_description,author_username FROM posts WHERE LOWER(title) LIKE ?;",
                (f"%{query}%",),
            )

            results = [dict(row) for row in searchData]
            for item in results:
                item["created_at"] = item["created_at"][:10]

            return jsonify(results)

    # In case of database error, display an error page
    except sqlite3.Error as e:
        logging.error(f"sqlite3 Error: {e}")
        return render_template("error.html", rtnvalue="Something went wrong")



# Route for searching posts in a specific blog

@app.route("/searchBlogResults", methods=["POST"])
def search_blog_results():

    # Get the input from the user
    data = request.get_json()
    query = data.get("q", "").lower()
    username = data.get("username", "")
    print(query)
    print(username)

    try:
        # Connect to the database and access the data by rows using row_factory object
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            searchData = cursor.execute(
                "SELECT id,title,created_at,post_description,author_username FROM posts WHERE author_username = ? AND LOWER(title) LIKE ?;",
                (username,f"%{query}%"),
            )

            results = [dict(row) for row in searchData]
            print(results)
            for item in results:
                item["created_at"] = item["created_at"][:10]

            return jsonify(results)

    # In case of database error, display an error page
    except sqlite3.Error as e:
        logging.error(f"sqlite3 Error: {e}")
        return render_template("error.html", rtnvalue="Something went wrong")



# Route for displaying all tags and allowing users to filter posts by tag by following the link


@app.route("/tags")
def tags():

    try:
        # Connect to the database and access the data by rows using row_factory object
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            # Get all the tags
            tags = cursor.execute("SELECT name FROM tags;")

            # Display all the tags that can be associated with a post
            return render_template("tags.html", tags=tags)

    # In case of database error, display an error page
    except sqlite3.Error as e:
        logging.error(f"sqlite Error: {e}")
        return render_template("error.html", rtnvalue="Something went wrong")


# Route for displaying posts associated with a specific tag


@app.route("/search/Tag")
def postsOfTag():

    tag_name = request.args.get("idf")

    try:
        # Connect to the database and access the data by rows using row_factory object
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            # Get all the posts which contains the tag
            tag = cursor.execute(
                "SELECT id FROM tags WHERE name = ?;", (tag_name,)
            ).fetchone()
            tag_id = tag["id"]
            posts = cursor.execute(
                "SELECT * FROM posts WHERE id IN (SELECT post_id FROM post_tags WHERE tag_id = ?);",
                (tag_id,),
            ).fetchall()

            # Display it to the user
            return render_template("postsByTag.html", tag_name=tag_name, posts=posts)

    # In case of database error, display an error page
    except sqlite3.Error as e:
        logging.error(f"sqlite3 Error : {e}")
        return render_template("error.html", rtnvalue="Something went wrong")


# Route for allowing users to login to their account


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":

        # If user is not logged in, display the login form
        if "user_id" not in session:
            return render_template("login.html")
        # If the user is already logged in, redirect the user to the homepage
        else:
            return redirect(url_for("main"))

    # Handle the authentication
    else:

        try:
            # Get the inputs of the user
            username = request.form.get("lgUsn")
            password = request.form.get("lgPswd")

            # Verify captcha completion
            if not xcaptcha.verify():
                return render_template(
                    "login.html",
                    error="Verify the captcha first",
                    username=username,
                    password=password,
                )

            # Check for blank inputs
            if not username or not password:
                return render_template(
                    "login.html",
                    error="Username and password cannot be blank",
                    username=username,
                    password=password,
                )

            # Create a connection to the database
            with sqlite3.connect("app.db") as con:
                cursor = con.cursor()
                credentials = cursor.execute(
                    "SELECT id, username, hash FROM users WHERE username = ?;",
                    (username,),
                ).fetchone()

            # Check if the user exists and the password entered by the user matches the password in the database for the given username
            if credentials and check_password_hash(credentials[2], password):
                session["user_id"] = credentials[0]
                session["username"] = credentials[1]
                return redirect(url_for("main"))

            else:
                return render_template(
                    "login.html",
                    error="Invalid username or password",
                    username=username,
                    password=password,
                )
        # Handle errors
        except sqlite3.Error as e:
            logging.error(f"SQlite3 error: {e}")
            return render_template(
                "error.html",
                rtnvalue="Sorry for the inconvenience! It looks like we messed up somewhere",
            )

        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return render_template(
                "error.html",
                rtnvalue="Sorry for the inconvenience! It looks like we messed up somewhere",
            )


# Route for logout


@app.route("/account/logout")
@login_required
def logout():

    # Clear the session
    session.clear()

    return redirect(url_for("login"))


# Route for registration


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        # If the user is already logged in, redirect to the homepage
        if "user_id" in session:
            return redirect(url_for("main"))
        # Else render a registration form
        else:
            return render_template("register.html")

    # Handle registration
    else:
        username = request.form.get("rgUsn")
        email = request.form.get("rgEmail")
        password = request.form.get("rgPswd")
        confirmPassword = request.form.get("rgConfirmPswd")

        # Verify the captcha

        if not xcaptcha.verify():
            return render_template(
                "register.html",
                error="Verify the captcha before clicking the register button",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )

        # Check for blank inputs
        if not username or not email or not password or not confirmPassword:
            return render_template(
                "register.html",
                error="All the fields are required",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )

        # Check for invalid email
        validation = validate_email(email)
        print(validation)

        # Return an error message in case of any errors during email validation
        if validation is None:
            return render_template(
                "register.html",
                error="Something went wrong",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )

        # Return an error message if the email is invalid without proceeding with registration
        if validation is False:
            return render_template(
                "register.html",
                error="Invalid email address",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )

        # Check if the passwords match
        if password != confirmPassword:
            return render_template(
                "register.html",
                error="Confirm password does not match",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )

        # Password strength and validation

        if ispwd_strong(password) is False:
            return render_template(
                "register.html",
                error="<strong>Weak password:</strong> Ensure your password meets the following guideline: <br><ul><li>Must be at least 8 characters long</li><li>Must contain at least one lowercase letter and one uppercase letter</li><li>Must contain at least one number and one special symbol</li></ul>",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )

        try:
            # Connect to the database and access the data by rows using row_factory object
            with sqlite3.connect("app.db") as con:
                con.row_factory = sqlite3.Row
                cursor = con.cursor()

                # Check if the username already exists
                username_exists = cursor.execute(
                    "SELECT id FROM users WHERE username = ?;", (username,)
                ).fetchone()
                if username_exists:
                    return render_template(
                        "register.html",
                        error="Username already exists",
                        username=username,
                        email=email,
                        password=password,
                        confirmPassword=confirmPassword,
                    )

                # Check if the email already exists
                email_exists = cursor.execute(
                    "SELECT * FROM users WHERE email = ?;", (email,)
                ).fetchone()
                if email_exists:
                    return render_template(
                        "register.html",
                        error="Email already exists",
                        username=username,
                        email=email,
                        password=password,
                        confirmPassword=confirmPassword,
                    )

                # Hash the password and add the user's entry to database

                hashed_password = generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO users (email,username,hash) VALUES(?,?,?);",
                    (
                        email,
                        username,
                        hashed_password,
                    ),
                )
                con.commit()

                # Automatically create a blog when a user registers for an account
                user = cursor.execute(
                    "SELECT id,username FROM users WHERE username = ?;", (username,)
                ).fetchone()
                blog_title = user["username"] + "'s blog"
                cursor.execute(
                    "INSERT into blog (author_id,author_username,title) VALUES (?,?,?);",
                    (user["id"], user["username"], blog_title),
                )
                con.commit()
                return render_template(
                    "register.html", success="Registration successfull."
                )

        # Handle Errors
        except sqlite3.Error as e:
            logging.error(f"sqlite3 error: {e}")
            return render_template(
                "register.html",
                error="Something went wrong",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )

        except ValueError as val_error:
            logging.error(f"Value error: {val_error}")
            return render_template(
                "register.html",
                error="Invalid data provided",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )

        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return render_template(
                "register.html",
                error="Something went wrong",
                username=username,
                email=email,
                password=password,
                confirmPassword=confirmPassword,
            )


# Route for account management


@app.route("/account")
@login_required
def manage_account():

    # Connect to the database and access the data by rows using row_factory object
    with sqlite3.connect("app.db") as con:
        cursor = con.cursor()
        get_email = cursor.execute(
            "SELECT email FROM users WHERE username = ?;", (session["username"],)
        ).fetchone()
        email = get_email[0]

    # Display all the currently present details of the user
    return render_template("account.html", username=session["username"], email=email)


# Route for changing email


@app.route("/account/change-email", methods=["GET", "POST"])
@login_required
def change_email():

    if request.method == "GET":
        # Display a form to change the email
        return render_template("change-email.html")

    # Handle the form submission
    else:
        # Get the inputs of the user
        newEmail = request.form.get("newEmail")
        verifyPswd = request.form.get("verifyPswd")

        # Check for blank inputs
        if not newEmail or not verifyPswd:
            return render_template(
                "change-email.html",
                error="New email and your current password cannot be empty",
                newEmail=newEmail,
                verifyPassword=verifyPswd,
            )

        # Check for invalid email
        validation = validate_email(newEmail)

        # Return an error message in case of any errors during email validation
        if validation is None:
            return render_template(
                "change-email.html",
                error="Something went wrong",
                newEmail=newEmail,
                verifyPassword=verifyPswd,
            )

        # Return an error message if the email is invalid without proceeding with registration
        if validation is False:
            return render_template(
                "change-email.html",
                error="Invalid email address",
                newEmail=newEmail,
                verifyPassword=verifyPswd,
            )

        try:
            # Create a connection to the database
            with sqlite3.connect("app.db") as con:
                cursor = con.cursor()

                # Get the password of the user
                row = cursor.execute(
                    "SELECT hash FROM users WHERE username = ?;", (session["username"],)
                ).fetchone()
                stPswd = row[0]

                # Verify if the user's actual password matches with the password in the form that the user submitted
                # if the passwords match, updated the user's email
                if check_password_hash(stPswd, verifyPswd):
                    cursor.execute(
                        "UPDATE users SET email = ? WHERE username = ?;",
                        (
                            newEmail,
                            session["username"],
                        ),
                    )
                    con.commit()
                    return render_template(
                        "change-email.html", success="Email updated successfully"
                    )

                # If the passwords do not match, display an error
                else:
                    return render_template(
                        "change-email.html",
                        error="Invalid password",
                        newEmail=newEmail,
                        verifyPassword=verifyPswd,
                    )

        # Handle database errors
        except sqlite3.Error as e:
            logging.error(f"sqlite3 Error: {e}")
            return render_template("error.html", rtnvalue="Something went wrong")


# Route for changing password


@app.route("/account/change-password", methods=["GET", "POST"])
@login_required
def change_password():

    if request.method == "GET":

        # Display the form to change the password
        return render_template("change-password.html")

    # Handle form submission
    else:

        # Get the form data
        currentPassword = request.form.get("currentPswd")
        newPassword = request.form.get("newPswd")
        ConfirmNewPassword = request.form.get("ConfirmNewPswd")

        # check for blank data
        if not currentPassword or not newPassword or not ConfirmNewPassword:
            return render_template(
                "change-password.html",
                error="Current password, new password and confirmation password cannot be blank",
                currentPassword=currentPassword,
                newPassword=newPassword,
                ConfirmNewPassword=ConfirmNewPassword,
            )

        # Display the error if the new password does not match the confirmation password
        if newPassword != ConfirmNewPassword:
            return render_template(
                "change-password.html",
                error="Confirmation password does not match",
                currentPassword=currentPassword,
                newPassword=newPassword,
                ConfirmNewPassword=ConfirmNewPassword,
            )

        # Password strength and validation

        if ispwd_strong(newPassword) is False:
            return render_template(
                "change-password.html",
                error="<strong>Weak password:</strong> Ensure your password meets the following guideline: <br><ul><li>Must be at least 8 characters long</li><li>Must contain at least one lowercase letter and one uppercase letter</li><li>Must contain at least one number and one special symbol</li></ul>",
                currentPassword=currentPassword,
                newPassword=newPassword,
                ConfirmNewPassword=ConfirmNewPassword,
            )

        try:
            with sqlite3.connect("app.db") as con:
                cursor = con.cursor()

                # Get the user's current password
                user = cursor.execute(
                    "SELECT hash FROM users WHERE username = ?;", (session["username"],)
                ).fetchone()

                # Check if the user's current password matches the value submitted in the form
                # if the password match, update the user's password
                if check_password_hash(user[0], currentPassword):
                    hashed_password = generate_password_hash(newPassword)
                    update_password = cursor.execute(
                        "UPDATE users SET hash = ? WHERE username = ?",
                        (hashed_password, session["username"]),
                    )
                    con.commit()
                    return render_template(
                        "change-password.html", success="Password changed successfully"
                    )

                # else return an error
                else:
                    return render_template(
                        "change-password.html",
                        error="Current password is invalid",
                        currentPassword=currentPassword,
                        newPassword=newPassword,
                        ConfirmNewPassword=ConfirmNewPassword,
                    )
        # Handle database errors
        except sqlite3.Error as e:
            logging.error(f"sqlite3 Error: {e}")
            return render_template("error.html", rtnvalue="Something went wrong")

        except ValueError as val_error:
            logging.error(f"Value error: {val_error}")
            return render_template("error.html", rtnvalue="Invalid data provided")


# Route for managing blog


@app.route("/manage-blog", methods=["GET", "POST"])
@login_required
def manage_blog():

    if request.method == "GET":
        try:
            with sqlite3.connect("app.db") as con:
                con.row_factory = sqlite3.Row
                cursor = con.cursor()

                # Get the user's blog details and display it to the user
                blog_detail = cursor.execute(
                    "SELECT title, about, igURL, xURL, author_username FROM blog WHERE author_id = ?;",
                    (session["user_id"],),
                ).fetchone()

                return render_template("manage-blog.html", blogDetail=blog_detail)

        # Handle database errors occurred during retrieval
        except sqlite3.Error as e:
            logging.error(f"sqlite3 Error: {e}")
            return render_template("error.html", rtnvalue="Something went wrong")

    # Handle changes made by the user in his/her blog
    else:
        try:
            # Get the changes
            title = request.form.get("title")
            about = request.form.get("aboutAuthor")
            image_file = request.files["photo"]
            igURL = request.form.get("igUrl")
            xURL = request.form.get("xUrl")

            # Return an error if the user has not given a title to their blog
            if not title:
                return render_template(
                    "manage-blog.html",
                    error="Blog title cannot be blank",
                    aboutAuthor=about,
                    igUrl=igURL,
                    xUrl=xURL,
                )

            with sqlite3.connect("app.db") as con:
                con.row_factory = sqlite3.Row
                cursor = con.cursor()

                # If the user uploaded their photo, store the photo in a dedicated folder and add the file's path to the user's blog entry in the database
                if image_file:
                    os.makedirs("uploads/images", exist_ok=True)
                    filename = os.path.join("uploads/images", image_file.filename)
                    image_file.save(filename)
                    cursor.execute(
                        "UPDATE blog SET title = ?, about = ?, igURL = ?, xURL = ?, imageURL = ? WHERE author_id = ?;",
                        (title, about, igURL, xURL, filename, session["user_id"]),
                    )
                    con.commit()

                # If the user has not uploaded their photo, update the blog without touching the image column in their entry
                else:
                    cursor.execute(
                        "UPDATE blog SET title = ?, about = ?, igURL = ?, xURL = ? WHERE author_id = ?;",
                        (title, about, igURL, xURL, session["user_id"]),
                    )
                    con.commit()

                # Get the updated details from the database
                blog_detail = cursor.execute(
                    "SELECT title, about, igURL, xURL FROM blog WHERE author_id = ?;",
                    (session["user_id"],),
                ).fetchone()

            # Display the updated details along with a success message
            return render_template(
                "manage-blog.html",
                blogDetail=blog_detail,
                success="Blog updated successfully",
            )

        # handle sqlite errors
        except sqlite3.Error as e:
            logging.error(f"sqlite3 Error: {e}")
            return render_template("error.html", rtnvalue="Something went wrong")


# Route for creating a post


@app.route("/manage-blog/create-post", methods=["GET", "POST"])
@login_required
def createPost():

    if request.method == "GET":
        try:
            with sqlite3.connect("app.db") as con:
                con.row_factory = sqlite3.Row
                cursor = con.cursor()

                # Get all the tags from the database
                tags = cursor.execute("SELECT * FROM tags;")

                # Display a form to create a post and allow users to add tags(retrieved above) to their post
                return render_template("create-post.html", tags=tags)
        except sqlite3.Error as e:
            logging.error(f"sqlite3 Error: {e}")
            return render_template("error.html", rtnvalue="Something went wrong")

    # Handle form submission for new post creation
    else:

        try:
            # Get the form data
            postTitle = request.form.get("postTitle")
            postDescription = request.form.get("postDescription")
            postTags = request.form.getlist("tags[]")
            postContent = request.form.get("content")

            # Connect to the database and access the data by rows using row_factory object
            with sqlite3.connect("app.db") as con:
                con.row_factory = sqlite3.Row
                cursor = con.cursor()

                # check for blank inputs
                if (
                    not postTitle
                    or not postDescription
                    or not postTags
                    or not postContent
                ):
                    tags = cursor.execute("SELECT * FROM tags;")
                    return render_template(
                        "create-post.html",
                        error="All the fields marked as * are required",
                        postTitle=postTitle,
                        postDescription=postDescription,
                        tags=tags,
                        post_content=postContent,
                        post_tags=postTags,
                    )

                # Sanitize the content using "clean (bleach)"" to prevent XSS attacks
                sanitized_content = clean(
                    postContent,
                    tags=bleach_tags,
                    attributes=bleach_attributes,
                    css_sanitizer=bleach_css_sanitizer,
                )

                # Create a new entry for the new post and add the form data
                cursor.execute(
                    "INSERT into posts (title, post_description, content, author_id, author_username) VALUES (?,?,?,?,?);",
                    (postTitle, postDescription, sanitized_content, session["user_id"],session["username"]),
                )

                # Get the id of the recently executed query and commit to database
                post_id = cursor.lastrowid
                con.commit()

                # Associate tags with the post
                for tag in postTags:
                    if tag:
                        cursor.execute(
                            "INSERT into post_tags (post_id,tag_id) VALUES (?,?);",
                            (post_id, tag),
                        )
                con.commit()

                # Display a success message if everything goes well
                return render_template(
                    "create-post.html", success="Post created successfully"
                )

        # Handle any database errors
        except sqlite3.Error as e:
            logging.error(f"sqlite3 error: {e}")
            return render_template(
                "create-post.html",
                error="Something went wrong",
                postTitle=postTitle,
                postDescription=postDescription,
            )


# Route for accessing posts of a user by their username


@app.route("/<author_username>")
def user_posts(author_username):

    try:
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            # Get the id of the user
            user = cursor.execute(
                "SELECT id FROM users WHERE username = ?;", (author_username,)
            ).fetchone()

            # if a user with the given username doesnot exist, return an error
            if not user:
                return render_template("error.html", rtnvalue="User doesn't exist")

            # Get the posts details of the posts published by given user
            posts = cursor.execute(
                "SELECT * FROM posts WHERE author_id = ? ORDER BY created_at DESC;", (user["id"],)
            ).fetchall()

            # Get the blog details of the requested user
            author = cursor.execute(
                "SELECT author_username,title, about, imageURL, igURL, xURL FROM blog WHERE author_username = ?;",
                (author_username,),
            ).fetchone()

            # Display the data to the visitor of the page
            return render_template(
                "blog.html",
                username=author_username,
                posts=posts,
                author=author,
            )

    # handle database errors during connection and data retrieval
    except sqlite3.Error as e:
        logging.error(f"sqlite3 Error: {e}")
        return render_template("error.html", rtnvalue="Something went wrong")


# Route for accessing a post by its id


@app.route("/<username>/posts/<int:post_id>")
def posts(username, post_id):

    try:
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            # Author details
            author = cursor.execute(
                "SELECT id FROM users WHERE username = ?;", (username,)
            ).fetchone()

            if not author:
                return render_template("error.html", rtnvalue="Blog doesn't exist")
            
            # Blog details
            blog = cursor.execute("SELECT title,author_username FROM blog WHERE author_username = ?;", (username,)).fetchone()

            # Get the post details of the post with given id
            post_details = cursor.execute(
                "SELECT * FROM posts WHERE id = ? AND author_id = ?;",
                (post_id, author["id"]),
            ).fetchone()

            # return an error if the post with given id does not exist
            if post_details == None:
                return render_template("error.html", rtnvalue="Post doesn't exist")

            # get the tags associated with the given post
            tags = cursor.execute(
                "SELECT tags.name,tags.id FROM tags JOIN post_tags ON tags.id = post_tags.tag_id WHERE post_tags.post_id = ?;",
                (post_id,),
            ).fetchall()

            # Get the comments

            comments = nest_comments(post_id)

            # Display the data to the visitor
            return render_template(
                "post.html",
                author=blog,
                post_details=post_details,
                tags=tags,
                top_level_comments=comments,
            )

    # Handle database exceptions
    except sqlite3.Error as e:
        logging.error(f"sqlite3 error: {e}")
        return render_template("error.html", rtnvalue="Something went wrong")


# Route for deleting a post


@app.route("/manage-blog/<posted_by>/delete-post", methods=["POST"])
@login_required
def delete_post(posted_by):

    # Check if the author and the user who request deletion is the same
    if session["username"] == posted_by:

        # Get the id of the post that the author(user) wants to delete
        post_id = request.args.get("idf")

        try:
            # Connect to the database and access the data by rows using row_factory object
            with sqlite3.connect("app.db") as con:

                con.row_factory = sqlite3.Row
                cursor = con.cursor()

                # Enable foreign key support
                cursor.execute("PRAGMA foreign_keys = ON")

                # Since cascading deletion is used, we don't have to manually remove the tags associated with a post to be deleted

                # Delete the post
                cursor.execute("DELETE FROM posts WHERE id = ?;", (post_id,))

                # Commit the changes to the database
                con.commit()

                # Return a success message and redirect the user to their blog
                flash("Post Deleted Successfully!")
                return redirect(f"/{posted_by}")

        # Escape the sqlite3 errors using exceptions
        except sqlite3.Error as e:
            logging.error(f"sqlite Error: {e}")
            return render_template("error.html", rtnvalue="Something went wrong")

    # If the request is not made by the author, return an access denied error
    else:
        return render_template(
            "error.html", rtnvalue="Access Denied: Suspicious attempt detected"
        )


# Route for editing a post


@app.route("/manage-blog/edit-post", methods=["GET", "POST"])
@login_required
def edit_post():

    post_id = request.args.get("id")

    # If post_id is blank, return an error
    if not post_id:
        return render_template("error.html", rtnvalue="Something went wrong")

    post_id = int(post_id)

    if request.method == "GET":

        try:

            with sqlite3.connect("app.db") as con:
                con.row_factory = sqlite3.Row
                cursor = con.cursor()

                # Get the id of the post's author
                author = cursor.execute(
                    "SELECT author_id FROM posts WHERE id = ?;", (post_id,)
                ).fetchone()

                # Check if the post with the given id exists
                if not author:
                    return render_template(
                        "error.html", rtnvalue="It looks like the post Doesn't exist"
                    )

                # Check if the author of the post and the logged in user are same
                if author["author_id"] != session["user_id"]:
                    return render_template(
                        "error.html",
                        rtnvalue="Access Denied: Suspicious attempt detected",
                    )

                # Get the post details
                post_detail = cursor.execute(
                    "SELECT id,title,content,author_id,post_description FROM posts WHERE id = ?;",
                    (post_id,),
                ).fetchone()

                # Get all the tags available
                tags = cursor.execute("SELECT * FROM tags;").fetchall()

                # store the tags associated with the post in a list so that it can be preselected (user can know the tags associated with the post)
                cursor.execute(
                    "SELECT tag_id FROM post_tags WHERE post_id = ?;", (post_id,)
                )

                associated_tags = [row["tag_id"] for row in cursor.fetchall()]

        # Skip the database errors with the help of exceptions
        except sqlite3.Error as e:
            logging.error(f"sqlite3 Error: {e}")
            return render_template("error.html", rtnvalue="Something went wrong")

        # Pass the post details to the template and display it to the author
        return render_template(
            "edit-post.html",
            postDetail=post_detail,
            tags=tags,
            associated_tags=associated_tags,
        )

    # Handling changes to the post
    else:
        try:
            # Get the changes
            postTitle = request.form.get("postTitle")
            postDescription = request.form.get("postDescription")
            postTags = request.form.getlist("tags[]")
            postContent = request.form.get("content")

            with sqlite3.connect("app.db") as con:
                con.row_factory = sqlite3.Row
                cursor = con.cursor()

                # Check for blank data
                if (
                    not postTitle
                    or not postDescription
                    or not postTags
                    or not postContent
                ):
                    tags = cursor.execute("SELECT * FROM tags;")

                    return render_template(
                        "edit-post.html",
                        error="All the fields marked as * are required",
                        postTitle=postTitle,
                        postDescription=postDescription,
                        tags=postTags,
                    )

                # Sanitize the content using "clean (bleach)"" to prevent XSS attacks
                sanitized_content = clean(
                    postContent,
                    tags=bleach_tags,
                    attributes=bleach_attributes,
                    css_sanitizer=bleach_css_sanitizer,
                )

                # Get the id of the associated tags
                associated_tags = cursor.execute(
                    "SELECT tag_id FROM post_tags WHERE post_id = ?;", (post_id,)
                ).fetchall()

                # Convert the dictionary to a list. It can be used as an array in jquery for updated preselected values
                exst_tags = [int(row["tag_id"]) for row in associated_tags]

                # Convert the updated tags list
                int_tags = [int(tag) for tag in postTags]

                # Create a list of tags that were newly added
                added_tags = [int(tag) for tag in int_tags if tag not in exst_tags]

                # List all the deleted tags

                deleted_tags = [int(tag) for tag in exst_tags if tag not in int_tags]

                # Update the post
                cursor.execute(
                    "UPDATE posts SET title = ?, post_description = ?, content = ? WHERE id = ?;",
                    (postTitle, postDescription, sanitized_content, post_id),
                )
                con.commit()

                # Associate tags with the post
                for tag in added_tags:
                    if tag:
                        cursor.execute(
                            "INSERT into post_tags (post_id,tag_id) VALUES (?,?);",
                            (post_id, tag),
                        )
                con.commit()

                # Delete the removed tags

                for tag in deleted_tags:
                    if tag:
                        cursor.execute(
                            "DELETE FROM post_tags WHERE tag_id = ?;", (tag,)
                        )

                # Get the post details
                post_detail = cursor.execute(
                    "SELECT id,title,content,author_id,post_description FROM posts WHERE id = ?;",
                    (post_id,),
                ).fetchone()

                # Get the tags

                tags = cursor.execute("SELECT * FROM tags;").fetchall()

                cursor.execute(
                    "SELECT tag_id FROM post_tags WHERE post_id = ?;", (post_id,)
                )

                associated_tags = [row["tag_id"] for row in cursor.fetchall()]

                return render_template(
                    "edit-post.html",
                    success="Post updated successfully",
                    postDetail=post_detail,
                    tags=tags,
                    associated_tags=associated_tags,
                )

        # Handle sqlite error
        except sqlite3.Error as e:
            logging.error(f"sqlite3 error: {e}")
            return render_template(
                "error.html",
                rtnvalue="Something went wrong",
            )


@app.route("/account/delete-account", methods=["POST"])
@login_required
def delete_account():

    # Get the password from the form
    password = request.form.get("verifyPwd")

    # Get the user's id
    id = int(session["user_id"])

    try:
        # Connect to the database and access the data by rows using row_factory object
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            # Get the user's password
            user = cursor.execute(
                "SELECT email,hash FROM users WHERE id = ?;", (id,)
            ).fetchone()

            if not password:
                return render_template(
                    "account.html",
                    deleteAccounterror="Password cannot be blank",
                    email=user["email"],
                    username=session["username"],
                )

            # Return an error if the user's password doesn't match with the form
            if not check_password_hash(user["hash"], password):
                return render_template(
                    "account.html",
                    deleteAccounterror="Invalid Password",
                    email=user["email"],
                    username=session["username"],
                )

            # Start a transaction
            cursor.execute("PRAGMA foreign_keys = ON;")

            # Delete the tags associated with all the user's posts
            cursor.execute(
                "DELETE FROM post_tags WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?);",
                (id,),
            )

            # Delete the user' posts
            cursor.execute("DELETE FROM posts WHERE author_id = ?;", (id,))

            # Delete the user's blog
            cursor.execute("DELETE FROM blog WHERE author_id = ?;", (id,))

            # Finally delete the user data
            cursor.execute("DELETE FROM users where id = ?;", (id,))

            # Comit the queries
            con.commit()

            # Log the user out by calling logout function
            logout()

    # Handle database errors
    except sqlite3.Error as e:
        # Revert the changes to the database in case of any errors
        con.rollback()
        logging.error(f"sqlite3 error: {e}")
        return render_template("error.html", rtnvalue="Something went wrong!")

    # After successfull deletion, redirect the user to the home page
    return redirect(url_for("main"))


# Handle 400 route
@app.route("/400")
def error():

    return render_template("error.html")


# Route to handle adding new comments to a post

@app.route("/<username>/add-comment/<int:post_id>", methods=["POST"])
def newComment(username,post_id):

    comment = request.form.get("newComment")

    if not comment:
        return render_template("error.html", rtnvalue="Comment cannot be empty")

    try:
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            cursor.execute(
                "INSERT into comments (username,content,post_id) VALUES (?,?,?);",
                (
                    session["username"],
                    comment,
                    post_id,
                ),
            )
            con.commit()

            flash("Comment posted :)")
            return redirect(f"/{username}/posts/{post_id}")

    except sqlite3.Error as e:
        logging.error(f"sqlite3 error: {e}")
        return render_template("error.html", rtnvalue="Something went wrong!")


# Route to handle replies to a comment
@app.route("/<username>/reply-to-comment/<int:post_id>/<int:parent_id>", methods=["POST"])
def addReply(username,post_id, parent_id):

    comment = request.form.get("replyToComment")

    if not comment:
        return render_template("error.html", rtnvalue="Reply cannot be empty")

    try:
        with sqlite3.connect("app.db") as con:
            con.row_factory = sqlite3.Row
            cursor = con.cursor()

            cursor.execute(
                "INSERT into comments (username,content,post_id,parent_id) VALUES (?,?,?,?);",
                (session["username"], comment, post_id, parent_id),
            )
            con.commit()

            flash("Reply posted :)")
            return redirect(f"/{username}/posts/{post_id}")

    except sqlite3.Error as e:
        logging.error(f"sqlite3 error: {e}")
        return render_template("error.html", rtnvalue="Something went wrong!")


if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
