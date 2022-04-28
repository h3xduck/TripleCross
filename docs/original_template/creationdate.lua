 os.remove("creationdate.timestamp")
 io.output("creationdate.timestamp"):write(os.date("\\edef\\tempa{\\string D:%Y%m%d%H%M%S}\n\\def\\tempb{%z}"))
