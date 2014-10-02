upload:
	s3cmd sync --acl-public --exclude=Makefile --exclude='.git/*' . s3://jcoledotus-blog-files/

.PHONY: upload
