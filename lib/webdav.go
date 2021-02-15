package lib

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
)

// CorsCfg is the CORS config.
type CorsCfg struct {
	Enabled        bool
	Credentials    bool
	AllowedHeaders []string
	AllowedHosts   []string
	AllowedMethods []string
	ExposedHeaders []string
}

// Config is the configuration of a WebDAV instance.
type Config struct {
	*User
	Auth    bool
	NoSniff bool
	Cors    CorsCfg
	Users   map[string]*User
}

var tmpl = template.Must(template.New("dirList.html").Funcs(template.FuncMap{
	"ByteCountIEC": func(b int64) string {
		const unit = 1024
		if b < unit {
			return fmt.Sprintf("%d B", b)
		}
		div, exp := int64(unit), 0
		for n := b / unit; n >= unit; n /= unit {
			div *= unit
			exp++
		}
		return fmt.Sprintf("%.1f %ciB",
			float64(b)/float64(div), "KMGTPE"[exp])
	},
}).Parse(`
<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{{or .Username "anonymous"}} - {{ .URLPath }} Listing - WebDAV Server</title>
    <meta name="description" content="Listing of {{ .URLPath }} by logged-in user {{or .Username "anonymous"}}, WebDAV Server">
    <style>
        .td-size-listing, .td-explain-empty-listing, .td-date-listing {
            text-align: center;
        }

        table {
            width: -webkit-fill-available;
        }

        .d-logged-in-user {
            float: right;
        }

		.p-sort-links > a {
			font-size: xx-small;
		}
    </style>
</head>

<body>

    <div class="d-logged-in-user">
        Currently logged in user: <span class="logged-in-user">{{or .Username "anonymous"}}</span>&nbsp;<a href="{{ .URLPrefix }}?logout=1" class="a-logout">Logout (Leave empty when prompted to input credentials)</a>
    </div>

    <h1>
        WebDAV server - <a href="{{ .URLPath }}">{{ .URLPath }}</a>
    </h1>

    <p class="p-explain-dir">
        The resource you are GETting is a directory. Index of this directory is listed below.
    </p>

	<p class="p-sort-links">
		<a href="?sort=name&desc=0&sepdir=0">NA▲☯</a> 
        <a href="?sort=name&desc=0&sepdir=1">NA▲🗀🗎</a> 
        <a href="?sort=name&desc=1&sepdir=0">NA▼☯</a> 
        <a href="?sort=name&desc=1&sepdir=1">NA▼🗀🗎</a> 
		&nbsp;|&nbsp;

        <a href="?sort=orig&desc=0&sepdir=0">OR</a> 
		&nbsp;|&nbsp;

		<a href="?sort=size&desc=0&sepdir=0">SZ▲☯</a> 
        <a href="?sort=size&desc=0&sepdir=1">SZ▲🗀🗎</a> 
        <a href="?sort=size&desc=1&sepdir=0">SZ▼☯</a> 
        <a href="?sort=size&desc=1&sepdir=1">SZ▼🗀🗎</a> 
		&nbsp;|&nbsp;

		<a href="?sort=mtime&desc=0&sepdir=0">MT▲☯</a> 
        <a href="?sort=mtime&desc=0&sepdir=1">MT▲🗀🗎</a> 
        <a href="?sort=mtime&desc=1&sepdir=0">MT▼☯</a> 
        <a href="?sort=mtime&desc=1&sepdir=1">MT▼🗀🗎</a> 
		&nbsp;|&nbsp;

		<a href="?sort=atime&desc=0&sepdir=0">AT▲☯</a> 
        <a href="?sort=atime&desc=0&sepdir=1">AT▲🗀🗎</a> 
        <a href="?sort=atime&desc=1&sepdir=0">AT▼☯</a> 
        <a href="?sort=atime&desc=1&sepdir=1">AT▼🗀🗎</a> 
		&nbsp;|&nbsp;

		<a href="?sort=ctime&desc=0&sepdir=0">CT▲☯</a> 
        <a href="?sort=ctime&desc=0&sepdir=1">CT▲🗀🗎</a> 
        <a href="?sort=ctime&desc=1&sepdir=0">CT▼☯</a> 
        <a href="?sort=ctime&desc=1&sepdir=1">CT▼🗀🗎</a> 
    </p>

    <table class="ta-listing">
        <thead>
            <tr class="header-listing">
                <th>Name</th>
                <th>Size</th>
                <th>Last Modified Date</th>
            </tr>
        </thead>
        <tbody>
            <tr class="tr-listing">
                <td class="td-name-listing">
                    <a class="a-name-listing" href="../">../ (Go to parent directory of current directory)</a>
                </td>
                <td class="td-size-listing">
                    N/A
                </td>
                <td class="td-date-listing">
                    N/A
                </td>
            </tr>
            <tr class="tr-listing">
                <td class="td-name-listing">
                    <a class="a-name-listing" href="./">./ (Current directory)</a>
                </td>
                <td class="td-size-listing">
                    N/A
                </td>
                <td class="td-date-listing">
                    N/A
                </td>
            </tr>

            {{ range .FileInfos }}
            <tr class="tr-listing">
                <td class="td-name-listing">
                    <a class="a-name-listing" href="./{{ .Name }}">{{ .Name }}{{ if .IsDir }}/{{ end }}</a>
                </td>
                <td class="td-size-listing">
                    {{ ByteCountIEC .Size }}
                </td>
                <td class="td-date-listing">
                    {{ .ModTime }}
                </td>
            </tr>
            {{ else }}
            <tr class="tr-listing">
                <td class="td-name-listing td-explain-empty-listing" colspan="3">
                    This is an empty directory.
                </td>
            </tr>
            {{ end }}
        </tbody>
    </table>



</body>

</html>
`))

//var tmpl = template.Must(template.New("list dir").Parse("xx"))

// ServeHTTP determines if the request is for this plugin, and if all prerequisites are met.
func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u := c.User
	requestOrigin := r.Header.Get("Origin")

	// Add CORS headers before any operation so even on a 401 unauthorized status, CORS will work.
	if c.Cors.Enabled && requestOrigin != "" {
		headers := w.Header()

		allowedHeaders := strings.Join(c.Cors.AllowedHeaders, ", ")
		allowedMethods := strings.Join(c.Cors.AllowedMethods, ", ")
		exposedHeaders := strings.Join(c.Cors.ExposedHeaders, ", ")

		allowAllHosts := len(c.Cors.AllowedHosts) == 1 && c.Cors.AllowedHosts[0] == "*"
		allowedHost := isAllowedHost(c.Cors.AllowedHosts, requestOrigin)

		if allowAllHosts {
			headers.Set("Access-Control-Allow-Origin", "*")
		} else if allowedHost {
			headers.Set("Access-Control-Allow-Origin", requestOrigin)
		}

		if allowAllHosts || allowedHost {
			headers.Set("Access-Control-Allow-Headers", allowedHeaders)
			headers.Set("Access-Control-Allow-Methods", allowedMethods)

			if c.Cors.Credentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}

			if len(c.Cors.ExposedHeaders) > 0 {
				headers.Set("Access-Control-Expose-Headers", exposedHeaders)
			}
		}
	}

	if r.Method == "OPTIONS" && c.Cors.Enabled && requestOrigin != "" {
		return
	}

	// Logout
	if r.URL.Query().Get("logout") == "1" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(401)
		fmt.Fprintln(w, `Logged out. Please go <a href="./">back</a> to log in again.`)
		return
	}

	// Authentication
	if c.Auth {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		// Gets the correct user for this request.
		username, password, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Not authorized", 401)
			return
		}

		user, ok := c.Users[username]
		if !ok {
			http.Error(w, "Not authorized", 401)
			return
		}

		if !checkPassword(user.Password, password) {
			log.Println("Wrong Password for user", username)
			http.Error(w, "Not authorized", 401)
			return
		}

		u = user
	} else {
		// Even if Auth is disabled, we might want to get
		// the user from the Basic Auth header. Useful for Caddy
		// plugin implementation.
		username, _, ok := r.BasicAuth()
		if ok {
			if user, ok := c.Users[username]; ok {
				u = user
			}
		}
	}

	// Checks for user permissions relatively to this PATH.
	noModification := r.Method == "GET" || r.Method == "HEAD" ||
		r.Method == "OPTIONS" || r.Method == "PROPFIND"
	if !u.Allowed(r.URL.Path, noModification) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.Method == "HEAD" {
		w = newResponseWriterNoBody(w)
	}

	// Excerpt from RFC4918, section 9.4:
	//
	// 		GET, when applied to a collection, may return the contents of an
	//		"index.html" resource, a human-readable view of the contents of
	//		the collection, or something else altogether.
	//
	// Get, when applied to collection, will return the HTML human-readable
	// view of dir structure.
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, u.Handler.Prefix) {
		realPath := strings.TrimPrefix(r.URL.Path, u.Handler.Prefix)
		info, err := u.Handler.FileSystem.Stat(context.TODO(), realPath)
		if err == nil && info.IsDir() {
			if !strings.HasSuffix(r.URL.Path, "/") {
				http.Redirect(w, r, r.URL.Path+"/", 302)
				return
			}

			f, err := u.Handler.FileSystem.OpenFile(context.TODO(), realPath, os.O_RDONLY, 0)
			if err != nil {
				http.Error(w, "Error opening directory", 500)
				return
			}
			fileInfos, err := f.Readdir(0)

			sortType := r.URL.Query().Get("sort")
			queryDesc := strings.ToLower(r.URL.Query().Get("desc"))
			isDesc := queryDesc == "1" || queryDesc == "true"
			querySepDir := strings.ToLower(r.URL.Query().Get("sepdir"))
			shouldSepDir := querySepDir == "1" || querySepDir == "true"

			if sortType != "orig" {
				sort.Slice(fileInfos, func(i, j int) bool {
					fileI := fileInfos[i]
					fileJ := fileInfos[j]
					if shouldSepDir {
						if fileI.IsDir() && !fileJ.IsDir() {
							return true
						}
						if !fileI.IsDir() && fileJ.IsDir() {
							return false
						}
					}
					var less bool
					if sortType == "size" {
						less = fileI.Size() < fileJ.Size()
					} else if sortType == "mtime" {
						less = fileI.ModTime().Before(fileJ.ModTime())
					} else if sortType == "atime" {
						valueI := reflect.ValueOf(fileI.Sys()).Elem().FieldByName("Atim").Field(0).Int()
						valueJ := reflect.ValueOf(fileJ.Sys()).Elem().FieldByName("Atim").Field(0).Int()
						less = valueI < valueJ
					} else if sortType == "ctime" {
						valueI := reflect.ValueOf(fileI.Sys()).Elem().FieldByName("Ctim").Field(0).Int()
						valueJ := reflect.ValueOf(fileJ.Sys()).Elem().FieldByName("Ctim").Field(0).Int()
						less = valueI < valueJ
					} else {
						// name
						less = fileI.Name() < fileJ.Name()
					}

					if isDesc {
						less = !less
					}
					return less
				})
			}

			f.Close()

			detailedFileInfos := make([]os.FileInfo, len(fileInfos))

			for i, fileInfo := range fileInfos {
				detailedFileInfos[i], err = u.Handler.FileSystem.Stat(context.TODO(), path.Join(realPath, fileInfo.Name()))

				if err != nil {
					http.Error(w, "Error stating file", 500)
					return
				}
			}

			if err != nil {
				http.Error(w, "Error reading directory", 500)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			err = tmpl.Execute(w, struct {
				Username  string
				URLPrefix string
				URLPath   string
				FileInfos []os.FileInfo
			}{
				Username:  u.Username,
				URLPrefix: u.Handler.Prefix,
				URLPath:   r.URL.Path,
				FileInfos: detailedFileInfos,
			})
			if err != nil {
				http.Error(w, "Error rendering template: "+err.Error(), 500)
				return
			}
			return
		}
	}

	// Runs the WebDAV.
	u.Handler.ServeHTTP(w, r)
}

// responseWriterNoBody is a wrapper used to suprress the body of the response
// to a request. Mainly used for HEAD requests.
type responseWriterNoBody struct {
	http.ResponseWriter
}

// newResponseWriterNoBody creates a new responseWriterNoBody.
func newResponseWriterNoBody(w http.ResponseWriter) *responseWriterNoBody {
	return &responseWriterNoBody{w}
}

// Header executes the Header method from the http.ResponseWriter.
func (w responseWriterNoBody) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Write suprresses the body.
func (w responseWriterNoBody) Write(data []byte) (int, error) {
	return 0, nil
}

// WriteHeader writes the header to the http.ResponseWriter.
func (w responseWriterNoBody) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}
