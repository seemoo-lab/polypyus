import sqlite3


class SqlController:
    controller = None
    cursor = None

    def __init__(self, Path):
        self.controller = sqlite3.connect(Path)
        self.controller.row_factory = self.dict_factory
        self.cursor = self.controller.cursor()

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def get_entry_by_id(self, table, id):
        self.cursor.execute(
            "SELECT * FROM " + str(table) + " WHERE ID=" + str(id) + ";"
        )
        result = self.cursor.fetchall()
        if len(result) is 1:
            return result[0]
        else:
            return result

    def get_entry_by_owner_id(self, table, ownerId, ownerVar):
        self.cursor.execute(
            "SELECT * FROM "
            + table
            + " WHERE Owner="
            + str(ownerId)
            + " AND OwnerVariable='"
            + str(ownerVar)
            + "' ;"
        )
        result = self.cursor.fetchall()
        if len(result) is 1:
            return result[0]
        else:
            return result

    def get_entry_by_name(self, table, name):
        self.cursor.execute(
            "SELECT * FROM " + table + " WHERE name='" + str(name) + "';"
        )
        result = self.cursor.fetchone()
        return result

    def get_entry_by_owner_id_array(self, table, ownerId, ownerVar):
        self.cursor.execute(
            "SELECT * FROM "
            + table
            + " WHERE Owner="
            + str(ownerId)
            + " AND OwnerVariable='"
            + str(ownerVar)
            + "'  ORDER BY ArrayPos ASC;"
        )
        result = self.cursor.fetchall()
        if len(result) is 1:
            return result[0]
        else:
            return result
