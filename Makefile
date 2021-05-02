# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

LESSONS = $(wildcard packet*)
LESSONS_CLEAN = $(addsuffix _clean,$(LESSONS))

.PHONY: clean $(LESSONS) $(LESSONS_CLEAN)

all: $(LESSONS)
clean: $(LESSONS_CLEAN)

$(LESSONS):
	$(MAKE) -C $@

$(LESSONS_CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean
