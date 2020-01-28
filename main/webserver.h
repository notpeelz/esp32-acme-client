/*
 * Web server code, to go with the standalone.cpp sample application.
 *
 *  This assumes that the IoT device is fully reachable over the Internet.
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

esp_err_t http_resp_dir_html(httpd_req_t *req, const char *dirpath);
esp_err_t http_get_handler(httpd_req_t *req);
esp_err_t upload_post_handler(httpd_req_t *req);
void StartWebServer(void);
