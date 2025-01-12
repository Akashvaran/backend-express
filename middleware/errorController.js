const errorController = (err, req, res, next) => {
 

    if (err.name === "ValidationError") {
        const errors = Object.values(err.errors).map((el) => el.message);
        return res.status(400).json({
            status: "fail",
            type: "ValidationError",
            message: "Validation failed",
            errors,
        });
    }

    if (err.name === "CastError") {
        return res.status(400).json({
            status: "fail",
            type: "CastError",
            message: `Invalid ${err.path}: ${err.value}.`,
        });
    }
    if (err.code === 11000) {
        const duplicateField = Object.keys(err.keyValue)[0];
        const duplicateValue = err.keyValue[duplicateField];
        return res.status(400).json({
            status: "fail",
            type: "DuplicateFieldError",
            message: `Duplicate field value: '${duplicateValue}'. Please use a different ${duplicateField}.`,
        });
    }

    if (err.name === "UnauthorizedError") {
        return res.status(401).json({
            status: "fail",
            type: "UnauthorizedError",
            message: "Unauthorized access. Please provide valid credentials.",
        });
    }

    if (err.name === "ForbiddenError") {
        return res.status(403).json({
            status: "fail",
            type: "ForbiddenError",
            message: "You do not have permission to perform this action.",
        });
    }

    if (err.message && err.message.includes("not found")) {
        return res.status(404).json({
            status: "fail",
            type: "NotFoundError",
            message: err.message,
        });
    }

    if (err.status === 413) {
        return res.status(413).json({
            status: "fail",
            type: "PayloadTooLargeError",
            message: "Request payload is too large. Please reduce the size of the request.",
        });
    }
    if (err.name === "SyntaxError" && err.message.includes("JSON")) {
        return res.status(400).json({
            status: "fail",
            type: "SyntaxError",
            message: "Invalid JSON payload. Please check your request body.",
        });
    }

    if (err.status === 429) {
        return res.status(429).json({
            status: "fail",
            type: "RateLimitError",
            message: "Too many requests. Please try again later.",
        });
    }

    if (err.name === "MongoServerError") {
        return res.status(500).json({
            status: "error",
            type: "MongoServerError",
            message: "Database error occurred.",
            error: err.message,
        });
    }

    res.status(500).json({
        status: "error",
        type: "InternalServerError",
        message: "An unexpected error occurred",
        error: err.message,
    });
};

export default errorController;
