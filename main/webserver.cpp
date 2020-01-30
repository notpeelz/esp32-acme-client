/*
 * Web server code, to go with the standalone.cpp sample application.
 *
 * This assumes that the IoT device is fully reachable over the Internet.
 *
 * Copyright (c) 2020 Danny Backx
 *
 * In large part, this is a simplified version of code in esp-idf sample
 * examples/protocols/http_server/file_serving/main/file_server.c .
 *
 * This example code is in the Public Domain (or CC0 licensed, at your option.)
 *
 * Unless required by applicable law or agreed to in writing, this
 * software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 */

/*
 * Note it is NOT RECOMMENDED to enable this functionality in a device
 * that's remotely accessible.
 *
 * This is a BLATANT SECURITY HOLE.
 */
#define	UNSECURE_I_KNOW_WHAT_I_AM_DOING

#include <Arduino.h>
#include <esp_spiffs.h>
#include <esp_wifi.h>

#include <esp_event_loop.h>
#include <esp_http_server.h>
#include <dirent.h>

#include "webserver.h"
#include "Acme.h"

static const char *ws_tag = "webserver";

#ifdef	UNSECURE_I_KNOW_WHAT_I_AM_DOING
/*
 * Read a directory. Simplified version of a function in esp-idf sample
 * examples/protocols/http_server/file_serving/main/file_server.c .
 */
esp_err_t http_resp_dir_html(httpd_req_t *req, const char *dirpath)
{
    char entrypath[64];
    char entrysize[16];

    struct dirent *entry;
    struct stat entry_stat;

    DIR *dir = opendir(dirpath);
    const size_t dirpath_len = strlen(dirpath);

    /* Retrieve the base path of file storage to construct the full path */
    strlcpy(entrypath, dirpath, sizeof(entrypath));

    if (!dir) {
        ESP_LOGE(ws_tag, "Failed to stat dir : %s", dirpath);
        /* Respond with 404 Not Found */
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Directory does not exist");
        return ESP_FAIL;
    }

    /* Send HTML file header */
    httpd_resp_sendstr_chunk(req, "<!DOCTYPE html><html><body>");

    /* Send file-list table definition and column labels */
    httpd_resp_sendstr_chunk(req,
        "<table class=\"fixed\" border=\"1\">"
        "<thead><tr><th>Name</th><th>Size (Bytes)</th></tr></thead>"
        "<tbody>");

    /* Iterate over all files / folders and fetch their names and sizes */
    while ((entry = readdir(dir)) != NULL) {
        strlcpy(entrypath + dirpath_len, entry->d_name, sizeof(entrypath) - dirpath_len);
        if (stat(entrypath, &entry_stat) == -1) {
            ESP_LOGE(ws_tag, "Failed to stat : %s", entry->d_name);
            continue;
        }
        sprintf(entrysize, "%ld", entry_stat.st_size);
        ESP_LOGI(ws_tag, "Found : %s (%s bytes)", entry->d_name, entrysize);

        /* Send chunk of HTML file containing table entries with file name and size */
        httpd_resp_sendstr_chunk(req, "<tr><td><a href=\"");
        httpd_resp_sendstr_chunk(req, req->uri);
        httpd_resp_sendstr_chunk(req, entry->d_name);
        if (entry->d_type == DT_DIR) {
            httpd_resp_sendstr_chunk(req, "/");
        }
        httpd_resp_sendstr_chunk(req, "\">");
        httpd_resp_sendstr_chunk(req, entry->d_name);
        httpd_resp_sendstr_chunk(req, "</a></td><td>");
        httpd_resp_sendstr_chunk(req, entrysize);
        httpd_resp_sendstr_chunk(req, "</td></tr>\n");
    }
    closedir(dir);

    /* Finish the file list table */
    httpd_resp_sendstr_chunk(req, "</tbody></table>");

    /* Send remaining chunk of HTML file to complete it */
    httpd_resp_sendstr_chunk(req, "</body></html>");

    /* Send empty chunk to signal HTTP response completion */
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}
#endif

/*
 * Rather simplistic "download file" handler : URI should be file name, no stripping.
 */
esp_err_t http_get_handler(httpd_req_t *req) {
  FILE *fd = NULL;
  struct stat file_stat;

  ESP_LOGI(ws_tag, "%s: %s", __FUNCTION__, req->uri);

  /* If name has trailing '/', respond with directory contents */
  if (req->uri[strlen(req->uri) - 1] == '/') {
#ifdef	UNSECURE_I_KNOW_WHAT_I_AM_DOING
    return http_resp_dir_html(req, req->uri);
#else
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Not configured to read directory");
    return ESP_FAIL;
#endif
  }

  if (stat(req->uri, &file_stat) == -1) {
    ESP_LOGE(ws_tag, "Failed to stat file : %s", req->uri);

    /* Respond with 404 Not Found */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File does not exist");
    return ESP_FAIL;
  }

  if ((fd = fopen(req->uri, "r")) == 0) {
    ESP_LOGE(ws_tag, "Failed to read existing file : %s", req->uri);

    /* Respond with 500 Internal Server Error */
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
    return ESP_FAIL;
  }

  ESP_LOGI(ws_tag, "Sending file : %s (%ld bytes)...", req->uri, file_stat.st_size);
  httpd_resp_set_type(req, "text/plain");

  static char chunk[512];
  /* Retrieve the pointer to scratch buffer for temporary storage */
  size_t chunksize;
  do {
    /* Read file in chunks into the scratch buffer */
    chunksize = fread(chunk, 1, sizeof(chunk), fd);

    /* Send the buffer contents as HTTP response chunk */
    if (httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) {
      fclose(fd);
      ESP_LOGE(ws_tag, "File sending failed!");
      /* Abort sending file */
      httpd_resp_sendstr_chunk(req, NULL);
      /* Respond with 500 Internal Server Error */
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
      return ESP_FAIL;
    }

    /* Keep looping till the whole file is sent */
  } while (chunksize != 0);

  /* Close file after sending complete */
  fclose(fd);
  ESP_LOGI(ws_tag, "File sending complete");

  /* Respond with an empty chunk to signal HTTP response completion */
  httpd_resp_send_chunk(req, NULL, 0);

  return ESP_OK;
}

#ifdef	UNSECURE_I_KNOW_WHAT_I_AM_DOING
/* Handler to upload a file onto the server */
esp_err_t upload_post_handler(httpd_req_t *req) {
    FILE *fd = NULL;
    struct stat file_stat;

    /* Skip leading "/upload" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = req->uri + sizeof("/upload") - 1;

    if (stat(filename, &file_stat) == 0) {
        ESP_LOGE(ws_tag, "File already exists : %s", filename);
        /* Respond with 400 Bad Request */
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "File already exists");
        return ESP_FAIL;
    }

    if ((fd = fopen(filename, "w")) == 0) {
        ESP_LOGE(ws_tag, "Failed to create file : %s", filename);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to create file");
        return ESP_FAIL;
    }

    ESP_LOGI(ws_tag, "Receiving file : %s...", filename);

    /* Retrieve the pointer to scratch buffer for temporary storage */
    char buf[512];
    int received;

    /* Content length of the request gives the size of the file being uploaded */
    int remaining = req->content_len;

    while (remaining > 0) {

        ESP_LOGI(ws_tag, "Remaining size : %d", remaining);

#ifndef MIN
#define MIN(a,b) ((a < b) ? a : b)
#endif
        /* Receive the file part by part into a buffer */
        if ((received = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
            if (received == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry if timeout occurred */
                continue;
            }

            /* In case of unrecoverable error, close and delete the unfinished file*/
            fclose(fd);
            unlink(filename);

            ESP_LOGE(ws_tag, "File reception failed!");
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive file");
            return ESP_FAIL;
        }

        /* Write buffer content to file on storage */
        if (received && (received != fwrite(buf, 1, received, fd))) {
            /* Couldn't write everything to file!
             * Storage may be full? */
            fclose(fd);
            unlink(filename);

            ESP_LOGE(ws_tag, "File write failed!");
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to write file to storage");
            return ESP_FAIL;
        }

        /* Keep track of remaining size of
         * the file left to be uploaded */
        remaining -= received;
    }

    /* Close file upon upload completion */
    fclose(fd);
    ESP_LOGI(ws_tag, "File reception complete");

    /* Redirect onto root to see the updated file list */
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_sendstr(req, "File uploaded successfully");
    return ESP_OK;
}
#endif

void StartWebServer(void) {
  esp_err_t	err;

  ESP_LOGI(ws_tag, "Starting web server ...");

  httpd_uri_t wsconf;
  wsconf.method = HTTP_GET;
  wsconf.handler = http_get_handler;
  wsconf.user_ctx = (void *)"<html><title>ESP32 test</title><body>This is a test page</body></html>";

  httpd_handle_t	webserver = NULL;
  httpd_config_t	wsconfig = HTTPD_DEFAULT_CONFIG();
  wsconfig.uri_match_fn = httpd_uri_match_wildcard;

  if (httpd_start(&webserver, &wsconfig) == ESP_OK) {
    wsconf.uri = "/*.html";
    if ((err = httpd_register_uri_handler(webserver, &wsconf)) != ESP_OK) {
      ESP_LOGE(ws_tag, "%s: failed to register %s (%d %s)", __FUNCTION__, wsconf.uri,
        err, esp_err_to_name(err));
    }
    wsconf.uri = "/*.ico";
    if ((err = httpd_register_uri_handler(webserver, &wsconf)) != ESP_OK) {
      ESP_LOGE(ws_tag, "%s: failed to register %s (%d %s)", __FUNCTION__, wsconf.uri,
        err, esp_err_to_name(err));
    }

#ifdef	UNSECURE_I_KNOW_WHAT_I_AM_DOING
    wsconf.uri = "/spiffs/*";
    if ((err = httpd_register_uri_handler(webserver, &wsconf)) != ESP_OK) {
      ESP_LOGE(ws_tag, "%s: failed to register %s (%d %s)", __FUNCTION__, wsconf.uri,
        err, esp_err_to_name(err));
    }

    wsconf.uri = "/upload/*";
    wsconf.method = HTTP_POST;
    if ((err = httpd_register_uri_handler(webserver, &wsconf)) != ESP_OK) {
      ESP_LOGE(ws_tag, "%s: failed to register %s (%d %s)", __FUNCTION__, wsconf.uri,
        err, esp_err_to_name(err));
    }
#endif
    acme->setWebServer(webserver);
    return;
  }

  ESP_LOGE(ws_tag, "Error starting web server");
}
