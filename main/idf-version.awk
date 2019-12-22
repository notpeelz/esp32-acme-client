function vers(from) {
  printf("-DIDF_MAJOR_VERSION=%d ", substr(from, 2, 1))
  printf("-DIDF_MINOR_VERSION=%d ", substr(from, 4, 1))
  if (substr(from, 6, 3) == "dev") {
    printf("-DIDF_DEV_VERSION=%d ", substr(from, 10, 3))
  }
}

{
 vers($0)
 exit
}
#
BEGIN {
  FROM=ARGV[1]
  ARGC=2
  ARGV[1] = "-"
}
{
  vers(FROM)
}

#
# acer: {2} git describe --always --tags --dirty
# v4.0-dev-447-g689032650-dirty
#
