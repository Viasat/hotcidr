def parse(s):
    try:
        return Port(int(s))
    except ValueError:
        if s == "all":
            return Port(None)
        else:
            start, _, end = s.partition('-')
            try:
                return Port(int(start), int(end))
            except ValueError:
                return None


class Port(object):
    def __init__(self, fromport, toport=None):
        #assert(isinstance(fromport, int))
        #assert(isinstance(toport, int))
        self._fromport = fromport
        if toport:
            self._toport = toport
        else:
            self._toport = fromport

    @property
    def fromport(self):
        return self._fromport

    @property
    def toport(self):
        return self._toport

    @property
    def all(self):
        return self.fromport == None and self.toport == None

    def yaml_str(self):
        if self.all:
            return "all"
        elif self.fromport < self.toport:
            return "%d-%d" % (self.fromport, self.toport)
        else:
            return self.fromport

    def __hash__(self):
        return hash((self.fromport, self.toport))

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
