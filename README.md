# Nginx Module: nginx-http-vkupload-module

## Description
Parses request body storing all files being uploaded to a directory specified by vkupload_file_path directive.

## Directives

### vkupload_pass

**Syntax:** <code><b>vkupload_pass</b> <i>location</i></code><br>
**Default:** —<br>
**Context:** `location`

Specifies location to pass request body to. File fields will be stripped
and replaced by fields, containing necessary information to handle
uploaded files.

### vkupload_field

**Syntax:** <code><b>vkupload_field</b> <i>name value</i></code><br>
**Default:** —<br>
**Context:** `location`

Specifies a form field(s) to generate for each uploaded file in request body passed to backend.

### vkupload_file_path

**Syntax:** <code><b>vkupload_file_path</b> <i>directory [level1 [level2]] ...</i></code><br>
**Default:** —<br>
**Context:** `location`

Specifies a directory to which output files will be saved to. The directory could be hashed.

### vkupload_file_access

**Syntax:** <code><b>vkupload_file_access</b> <i>mode</i></code><br>
**Default:** user:rw<br>
**Context:** `location`

Specifies access mode which will be used to create output files.

### vkupload_multipart

**Syntax:** <code><b>vkupload_multipart</b> <i>on | off</i></code><br>
**Default:** —<br>
**Context:** `location`

Enables multipart uploads.

### vkupload_multipart_field

**Syntax:** <code><b>vkupload_multipart_field</b> <i>name</i></code><br>
**Default:** —<br>
**Context:** `location`

Fields name with file content in multipart request.

### vkupload_resumable

**Syntax:** <code><b>vkupload_resumable</b> <i>on | off</i></code><br>
**Default:** —<br>
**Context:** `location`

Enables resumable uploads.
Protocol spec: http://www.grid.net.ru/nginx/resumable_uploads.en.html

### vkupload_resumable_session_zone

**Syntax:** <code><b>vkupload_resumable_session_zone</b> <i>name [size]</i></code><br>
**Default:** —<br>
**Context:** `location`

Shared memory zone name and size for resumable states.

## Variables

### $vkupload_file_path

Path to uploaded file

### $vkupload_file_md5

MD5 of uploaded file

### $vkupload_file_size

Size of uploaded file

### $vkupload_file_name

Name of uploaded file, get from "filename" from Content-Disposition header

### $vkupload_file_field

Field of uploaded file, get from "field" from Content-Disposition header
