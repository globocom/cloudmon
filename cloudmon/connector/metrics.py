# -*- coding: utf-8 -*-

"""
Classes to generate and treat metrics
"""

import cProfile
import pstats


class Metrics(object):
    def __init__(self):
        self.profile = cProfile.Profile()

    def start(self):
        self.profile.clear()
        self.profile.enable()

    def stop(self):
        self.profile.create_stats()
        ps = pstats.Stats(self.profile)
        return ps.total_tt
