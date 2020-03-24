import zlib
from collections import MutableSequence


class Block:
    def __init__(self, data=None):
        if data is None:
            self.type = "NONE"
            self.name = ""
            self.data = b""
        else:
            self._set_block_data(data=data)

    @property
    def block_data(self):
        return self._get_block_data(compress_data=False)

    @block_data.setter
    def block_data(self, block_data):
        self._set_block_data(data=block_data)

    @property
    def zblock_data(self):
        return self._get_block_data(compress_data=True)

    @zblock_data.setter
    def zblock_data(self, block_data):
        self._set_block_data(data=block_data)

    def _set_block_data(self, data):
        self._block_data = data
        # The first 4 Byte contain the type of the Block
        self.type = data[:4].decode("latin-1")
        # the following 128 Byte, contain the Name of the Block in latin-1
        # padded with 'NUL' '\0'
        self.name = data[4:132].decode("latin-1").rstrip("\0")
        # then there is a 32 bit Integer, that states the compressed
        # size/length of the data
        data_length = int.from_bytes(data[132:136], byteorder="little", signed=False)
        # right after that, there is another 32 bit Integer that states the
        # uncompressed size/length of the data.
        uncompressed_data_length = int.from_bytes(
            data[136:140], byteorder="little", signed=False
        )
        # then there is an 32 Bit Integer containing either a one or a zero, 1
        # = block data is compressed, 0 = block data is uncompressed
        if (
            int.from_bytes(data[140:144], byteorder="little") == 1
            and data_length != uncompressed_data_length
        ):
            self.compressed = True
        else:
            self.compressed = False
        # The Compressed and decompressed Data can each be found at offset 144
        # + the Length of the "self.data_length" Variable
        data_raw = data[144 : 144 + data_length]
        if self.compressed:
            self.data = zlib.decompress(data_raw)
        else:
            self.data = data_raw

    def _get_block_data(self, compress_data=False):
        """This Function should return All the Block Data in the correct Block Format, containing, the name, type and what not :D"""
        data_block = self.data
        uncompressed_length = len(data_block)
        if compress_data:
            data_block = zlib.compress(data_block)
            compress_data_bit = 1
        else:
            compress_data_bit = 0
        data = bytes(self.type, encoding="latin-1")
        data += bytes(self.name, encoding="latin-1").ljust(128, b"\0")
        data += len(data_block).to_bytes(length=4, byteorder="little")
        data += uncompressed_length.to_bytes(length=4, byteorder="little")
        data += compress_data_bit.to_bytes(length=4, byteorder="little")
        data += data_block
        return data


class TagBlock(Block):
    def __init__(self, data):
        """docstring :D"""
        Block.__init__(self, data)

    @staticmethod
    def create_tag_block(block_type, block_name, named_variables):
        tmp_tag_block = TagBlock(Block().block_data)
        tmp_tag_block.type = block_type
        tmp_tag_block.name = block_name
        tmp_tag_block.number_of_integer_variables = 0
        tmp_tag_block.number_of_string_varaibles = 0
        for variable in named_variables:
            if type(variable[1] == int):
                number_of_integer_variables = +1
                tmp_tag_block.named_variables.append(variable)
            elif type(variable[1 == str]):
                number_of_string_varaibles = +1
                tmp_tag_block.named_variables.append(variable)
        return tmp_tag_block

    def _get_named_integer_variables(self, data, count):
        #
        # Each named Integer Variable consists of 3 Parts:
        # - a 32bit Integer Variable that states the length of the name 'key_length'
        # - n Bytes containing said Name, where n is the length specified in the Integer beforhand 'key'
        # - a 32bit Integer containing the 'value' of the Named Integer
        # +------------------+-------------------+--------------+
        # | 4B  Int len(KEY) | nB KEY in LATIN-1 | 4B Int Value |
        # +------------------+-------------------+--------------+
        #
        if count != 0:
            key_length = int.from_bytes(data[:4], byteorder="little")
            key = data[4 : 4 + key_length].decode("latin-1")
            value = int.from_bytes(
                data[4 + key_length : 8 + key_length], byteorder="little"
            )
            self.named_variables.append((key, value))
            self._get_named_integer_variables(
                data=data[8 + key_length :], count=count - 1
            )
        else:
            self.str_data = data

    def _get_named_string_variables(self, data, count):
        #
        # Each named String Variable consists of 4 Parts:
        # - a 32bit Integer Variable that states the length of the name 'key_length'
        # - n Bytes containing said name, where n is the length specified in the Integer beforhand 'key'
        # - a 32bit Integer Variable that states the length of the value 'value_length'
        # - n Bytes containing said 'value', where n is the length specified in the Integer beforhand 'value_length'
        # +-----------------+-------------------+-------------------+---------------------+
        # | 4B Int len(KEY) | nB KEY in LATIN-1 | 4B Int len(Value) | nB Value in LATIN-1 |
        # +-----------------+-------------------+-------------------+---------------------+
        #
        if count != 0:
            key_length = int.from_bytes(data[:4], byteorder="little")
            key = data[4 : 4 + key_length].decode("latin-1")
            value_length = int.from_bytes(
                data[4 + key_length : 8 + key_length], byteorder="little"
            )
            value = data[8 + key_length : 8 + key_length + value_length].decode(
                "latin-1"
            )
            self.named_variables.append((key, value))
            self._get_named_string_variables(
                data=data[8 + key_length + value_length :], count=count - 1
            )
        else:
            self.str_data = data

    @property
    def data(self):
        # if self.named_variables.data_changed:
        if True:
            ints = list()
            strings = list()
            for variable in self.named_variables:
                if type(variable[1]) == int:
                    ints.append(variable)
                elif type(variable[1] == str):
                    strings.append(variable)
            tmp_ints = bytes(len(ints).to_bytes(length=4, byteorder="little"))
            for variable in ints:
                tmp_ints += len(bytes(variable[0], encoding="latin-1")).to_bytes(
                    length=4, byteorder="little"
                )
                tmp_ints += bytes(variable[0], encoding="latin-1")
                tmp_ints += variable[1].to_bytes(length=4, byteorder="little")
            tmp_strings = bytes(len(strings).to_bytes(length=4, byteorder="little"))
            for variable in strings:
                tmp_strings += len(bytes(variable[0], encoding="latin-1")).to_bytes(
                    length=4, byteorder="little"
                )
                tmp_strings += bytes(variable[0], encoding="latin-1")
                tmp_strings += len(bytes(variable[1], encoding="latin-1")).to_bytes(
                    length=4, byteorder="little"
                )
                tmp_strings += bytes(variable[1], encoding="latin-1")
            self._data = tmp_ints + tmp_strings
            # self.named_variables.data_changed = False
        return self._data

    @data.setter
    def data(self, data):
        self._data = data
        self.named_variables = list()
        # Integers
        self.number_of_integer_variables = int.from_bytes(data[:4], byteorder="little")
        self._get_named_integer_variables(
            data=data[4:], count=self.number_of_integer_variables
        )
        # Strings
        self.number_of_string_varaibles = int.from_bytes(
            self.str_data[:4], byteorder="little"
        )
        self._get_named_string_variables(
            data=self.str_data[4:], count=self.number_of_string_varaibles
        )


class TagBlockVariableList(MutableSequence):
    def __init__(self, data=None):
        self.data_changed = False
        super(TagBlockVariableList, self).__init__()
        if not (data is None):
            self._list = list(data)
        else:
            self._list = list()

    def append(self, val):
        list_idx = len(self._list)
        self.data_changed = True
        self.insert(list_idx, val)
