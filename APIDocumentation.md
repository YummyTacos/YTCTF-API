# API Documentation (API v1.0.0)
## Making requests
All queries to the API need to be presented in this form: `http://api.ctf.yummytacos.me/METHOD_NAME`. Like this for example: `http://api.ctf.yummytacos.me/tasks`

API supports four ways of passing parameters in requests:
- URL query string
- `application/x-www-form-urlencoded`
- `application/json` (except for uploading files)
- `multipart/form-data` (use to upload files)

The response contains a JSON object. On success, an object in Endpoints section is returned. Otherwise, object with `error_code` and human-readable `message` is returned. Some errors may also have an optional String field `key`, which can help to handle the error.

## Authentication
To use methods, which require authentication, confirmed account or admin rights, you must provide token as `Authorization` HTTP header like this: `Authorization: Bearer <token>`, where `<token>` is your token (you can get it by authenticating, see Endpoints section for more).

## Endpoints
### `/about`
Use this method to get information about this platform
#### Methods:
##### GET
About platform
###### Args:
- Nothing
###### Returns:
- `name` (`String`): Platform name
- `version` (`String`): Platform version
- `license` (`String`): Platform distribution license
- `license_url` (`String`): Platform distribution license URL
- `repository` (`String`): Platform repository URL
- `contact` (`String`): Contact name in case of questions
- `contact_url` (`String`): Contact URL in case of questions
- `uptime` (`Integer`): Platform uptime (seconds)

### `/article`
Use this method to retrieve article
#### Methods:
##### GET
Get article
###### Args:
- `id` (`Integer`, _required_): Article ID
###### Returns:
- `article` (`Article`): Article

### `/articles`
Use this method to retrieve articles
#### Methods:
##### GET
Get articles
###### Args:
- `category_id` (`Integer`, _optional_): If provided, filter articles by category, otherwise return all articles
###### Returns:
- `articles` (`List<Article>`): Resulting list of articles

### `/auth`
Use this method to authenticate in platform.
#### Methods:
##### POST
Authenticate
###### Args:
- `username` (`String`, _required_): Username for the user
- `password` (`String`, _required_): Password for the user
###### Returns:
- `token` (`String`): Token which can be used to authenticate API requests

### `/categories`
Use this method to retrieve all categories
#### Methods:
##### GET
Get categories
###### Args:
- Nothing
###### Returns:
- `categories` (`List<Category>`): Resulting list of categories

### `/category`
Use this method to retrieve category information
#### Methods:
##### GET
Get category
###### Args:
- `id` (`Integer`, _required_): Category ID
###### Returns:
- `category` (`Category`): Category

### `/recover`
Use this method to recover account password
#### Methods:
##### POST
Request password recovery email or confirm password recovery
###### Args:
- `code` (`String`, _optional_): If provided, try to recover account password, otherwise, request password recovery email
- `email` (`String`, _optional_): Email of account to recover
- `url` (`String`, _optional_): If provided, this URL will be used to provide alternative verification method
###### Returns:
- `token` (`String`): If account password recovery was requested and it succeeded, token, which can be used to log in and change password, empty string otherwise

### `/register`
Use this method to register in platform.
#### Methods:
##### POST
Register in platform. Send first request without captcha_id and captcha_data, then you will get captcha_id together with a "Captcha required" error. Solve it and send result as captcha_data back with captcha_id
###### Args:
- `username` (`String`, _required_): Username. Must contain only latin letters, digits, underscores and dots
- `first_name` (`String`, _required_): First name
- `last_name` (`String`, _optional_): Last name
- `email` (`String`, _required_): E-mail
- `password` (`String`, _required_): Password
- `captcha_id` (`String`, _optional_): ID of the captcha that can confirm your registration
- `captcha_data` (`String`, _optional_): Solved captcha that can confirm your registration
###### Returns:
- `user_id` (`Integer`): ID of successfully registered user

### `/task`
Use this method to retrieve task information or to send flags for the task.
#### Methods:
##### GET
Get task
###### Args:
- `id` (`Integer`, _required_): Task ID
###### Returns:
- `task` (`Task`): Task
##### POST
Send task flag _(requires authentication)_
###### Args:
- `id` (`Integer`, _required_): Task ID
- `flag` (`String`, _required_): Task flag
###### Returns:
- Nothing

### `/tasks`
Use this method to retrieve list of tasks
#### Methods:
##### GET
Get tasks
###### Args:
- Nothing
###### Returns:
- `tasks` (`List<Task>`): Resulting list of tasks

### `/user`
Use this method to retrieve information about the user
#### Methods:
##### GET
Get user info
###### Args:
- `id` (`Integer`, _optional_): User ID. If not provided, returns info about current user
###### Returns:
- `user` (`User`): User
##### PATCH
Edit current user info _(requires authentication)_
###### Args:
- `id` (`Integer`, _optional_): User ID to edit (requires admin rights)
- `username` (`String`, _optional_): New username
- `email` (`String`, _optional_): New email. Resets confirmation status, if present
- `first_name` (`String`, _optional_): New first name
- `last_name` (`String`, _optional_): New last name
- `password` (`String`, _optional_): New password
- `is_admin` (`Integer`, _optional_): If this is set to 0, removes admin rights, else if this is set to 1, sets admin rights (requires admin rights)
###### Returns:
- Nothing

### `/users`
Use this method to retrieve all users.
#### Methods:
##### GET
Get users
###### Args:
- Nothing
###### Returns:
- `users` (`List<User>`): Resulting list of users

### `/verify`
Use this method to verify user's email
#### Methods:
##### POST
Request email verification or verify email
###### Args:
- `code` (`String`, _optional_): If provided, try to verify email, otherwise, request email verification (requires authentication)
- `url` (`String`, _optional_): If provided, this URL will be used to provide alternative verification method
###### Returns:
- Nothing

### `/docs`
Use this method to retrieve API documentation
#### Methods:
##### GET
Get API documentation
###### Args:
- `method` (`String`, _optional_): If provided, return documentation for this method, otherwise return documentation for all methods
###### Returns:
- `doc` (`Mapping<str, str>`): Documentation in Markdown format. "_" key is documentation header, which describes how to make requests

### `/admin/article`
Use this method to manage articles
#### Methods:
##### POST
Create new article _(requires admin rights)_
###### Args:
- `title` (`String`, _required_): Article title
- `text` (`String`, _required_): Article text
- `category` (`Integer`, _required_): Category ID for article
###### Returns:
- `article` (`Article`): Created article
##### PATCH
Edit article _(requires admin rights)_
###### Args:
- `id` (`Integer`, _required_): Article ID
- `title` (`String`, _optional_): New article title
- `text` (`String`, _optional_): New article text
- `category` (`Integer`, _optional_): New category ID for article
###### Returns:
- `article` (`Article`): Edited article
##### DELETE
Delete article _(requires admin rights)_
###### Args:
- `id` (`Integer`, _required_): Article ID
###### Returns:
- Nothing

### `/admin/category`
Use this method to manage categories
#### Methods:
##### POST
Create new category _(requires admin rights)_
###### Args:
- `name` (`String`, _required_): Category name
###### Returns:
- `category` (`Category`): Created category
##### PATCH
Edit category _(requires admin rights)_
###### Args:
- `id` (`Integer`, _required_): Category ID
- `name` (`String`, _optional_): New category name
###### Returns:
- `category` (`Category`): Edited category
##### DELETE
Delete category _(requires admin rights)_
###### Args:
- `id` (`Integer`, _required_): Category ID
###### Returns:
- Nothing

### `/admin/task`
Use this method to manage tasks.
#### Methods:
##### POST
Create or propose new task _(requires confirmed account)_
###### Args:
- `title` (`String`, _required_): Task name
- `author` (`Integer`, _required_): If provided, user ID of task author (cannot be set on task proposals), otherwise current user ID
- `category` (`String`, _required_): Task category
- `points` (`Integer`, _required_): Task points, must be positive
- `description` (`String`, _required_): Task description
- `writeup` (`String`, _required_): Task write-up (solution)
- `flag` (`String`, _required_): Task flag
###### Returns:
- `task` (`Task`): Created task
##### PATCH
Edit task (if user is admin, this also confirms task proposal) _(requires confirmed account)_
###### Args:
- `id` (`Integer`, _required_): Task ID to edit
- `title` (`String`, _optional_): New task name
- `author` (`Integer`, _optional_): User ID of new task author
- `category` (`String`, _optional_): New task category
- `points` (`Integer`, _optional_): New task points, must be positive
- `description` (`String`, _optional_): New task description
- `writeup` (`String`, _optional_): New task write-up (solution)
- `flag` (`String`, _optional_): New task flag
###### Returns:
- `task` (`Task`): Edited task
##### DELETE
Delete task _(requires confirmed account)_
###### Args:
- `id` (`Integer`, _required_): Task ID to delete
###### Returns:
- Nothing

### `/admin/file`
Use this method to manage task files
#### Methods:
##### POST
Send file and attach it to task _(requires confirmed account)_
###### Args:
- `task_id` (`Integer`, _required_): Task ID
- `file` (`multipart/form-data`, _required_): File
###### Returns:
- `file` (`File`): Added file
##### DELETE
Delete file _(requires confirmed account)_
###### Args:
- `id` (`Integer`, _required_): File ID to delete
###### Returns:
- Nothing