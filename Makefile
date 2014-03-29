upload:
	s3cmd sync --exclude=Makefile --exclude='.git/*' . s3://jcoledotus-blog-files/

.PHONY: upload
