#!/usr/bin/env python3
import re
from typing import List
import logging
import mysql.connector
import os


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """Filters a log line"""
    ext, rep = (lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
                lambda x: r'\g<field>={}'.format(x),
                )
    return re.sub(ext(fields, separator), rep(redaction), message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filters values in incoming log records using filter_datum"""
        return filter_datum(self.fields, self.REDACTION,
                            super(RedactingFormatter, self).format(record), self.SEPARATOR)


def get_logger() -> logging.Logger:
    """Returns a Logger object"""
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(
        ['name', 'levelname', 'asctime', 'message']))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Returns a connector object"""
    username = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    db = mysql.connector.connect(
        user=username, password=password, host=host, database=db_name)
    return db


def main() -> None:
    """Main function"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    fields = [i[0] for i in cursor.description]
    logger = get_logger()
    for row in cursor:
        message = ';'.join([str(i) for i in row])
        logger.info(message, extra={'fields': fields})

    cursor.close()
    db.close()

    return None


if __name__ == "__main__":
    # run only the main function when this module is executed
    main()
