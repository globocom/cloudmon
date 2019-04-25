# -*- coding: utf-8 -*-


from Queue import Queue
from random import shuffle

class ProxyQueue(Queue):
    def __init__(self, percent):
        Queue.__init__(self)
        self.elements = self.get_elements(percent)
        self.feed(self.elements)

    def get_elements(self, percent):
        elements = []
        for k,v in percent.iteritems():
            for i in range(v):
                elements.append(k)
        return elements

    def feed(self, elements):
        shuffle(elements)
        for i in elements:
            self.put(i)

    def get_next(self):
        if self.empty():
            self.feed(self.elements)
        return self.get()
