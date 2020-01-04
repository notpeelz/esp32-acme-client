#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

PROJECT_NAME := acmeclient

IDF_PATH = /home/danny/src/github/esp32/esp-idf-v3.3.1

COMPONENT_SRCDIRS = libraries/arduinojson libraries/ftpclient

include $(IDF_PATH)/make/project.mk
