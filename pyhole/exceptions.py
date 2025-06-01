class ApiError(Exception):
    """Base class for exceptions in this module"""
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class AuthenticationRequiredException(ApiError):
    """Incorrect or empty credential fields included in the request"""
    def __init__(self, message, response={}):
        self.message = message
        self.response = response

    def __str__(self):
        return self.message


class ForbiddenException(ApiError):
    """403 response"""
    def __init__(self, message, response={}):
        self.message = message
        self.response = response

    def __str__(self):
        return self.message


class BadRequestException(ApiError):
    """400 response"""
    def __init__(self, message, response={}):
        self.message = message
        self.response = response

    def __str__(self):
        return self.message


class DataFormatException(ApiError):
    """Unexpected data format, e.g. input too long"""
    def __init__(self, message, response={}):
        self.message = message
        self.response = response

    def __str__(self):
        return self.message


class UniqueConstraintException(ApiError):
    """Database error"""
    def __init__(self, message, response={}):
        self.message = message
        self.response = response

    def __str__(self):
        return self.message


class ItemNotFoundException(ApiError):
    """404 response"""
    def __init__(self, message, response={}):
        self.message = message
        self.response = response

    def __str__(self):
        return self.message


class RateLimitExceededException(ApiError):
    """Too many requests or the maximum number of sessions reached"""
    def __init__(self, message, response={}):
        self.message = message
        self.response = response

    def __str__(self):
        return self.message
