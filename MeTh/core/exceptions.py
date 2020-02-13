class MeTHException(Exception):
    def __init__(self, msg = ""):
        super(MeTHException, self).__init__(msg)


class OptionValidationError(MeTHException):
    pass


class StopThreadPoolExecutor(MeTHException):
    pass