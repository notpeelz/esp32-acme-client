#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

PROJECT_NAME := acmeclient

IDF_PATH = /home/danny/src/github/esp32/git/3.2/esp-idf
# IDF_PATH = /home/danny/src/github/esp32/git/esp-idf-3.2.2/esp-idf

COMPONENT_SRCDIRS = libraries/arduinojson libraries/ftpclient

include $(IDF_PATH)/make/project.mk
