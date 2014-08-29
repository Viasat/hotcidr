def parse(s):
    try:
        return Port(int(s))
    except ValueError:
        start, _, end = s.partition('-')
        return Port(start, end)


class Port(object):
    def __init__(self, fromport, toport=None):
        self._fromport = int(fromport)
        if toport:
            self._toport = int(toport)
        else:
            self._toport = fromport

    @property
    def fromport(self):
        return self._fromport

    @property
    def toport(self):
        return self._toport

    def yaml_str(self):
        if self.fromport < self.toport:
            return "%d-%d" % (self.fromport, self.toport)
        elif self.fromport == self.toport:
            return self.fromport
        else:
            return self.fromport

    def __hash__(self):
        return hash((self.fromport, self.toport))

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
