# -*- coding: utf-8 -*-
"""Notation of a Loi 25 obligation: main Act and section, e.g. 'P-39.1 s. 3.8' or 'P-39.1 s. 3.5 (2nd para.)'.
Regulation references stay in the concept's note and definition."""

def loi25_notation(act, section):
    return "%s s. %s" % (act.split(";")[0].strip(), section.split(";")[0].strip())
