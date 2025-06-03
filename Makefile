#-*- mode: makefile; -*-

MODULE = Amazon::Cognito::DecodeToken

PERL_MODULES = \
    lib/Amazon/Cognito/DecodeToken.pm

VERSION := $(shell perl -I lib -M$(MODULE) -e 'print $$BLM::Startup::S3::VERSION;')

TARBALL = Amazon-Cognito-DecodeToken-$(VERSION).tar.gz

$(TARBALL): buildspec.yml $(PERL_MODULES) requires test-requires README.md
	make-cpan-dist.pl -b $<

README.md: $(PERL_MODULES)
	pod2markdown $< > $@

clean:
	rm -f *.tar.gz
