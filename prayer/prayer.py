from prayer.blocks import Block


class Pray:
    # This list contains all the Blocks the given PRAY file contains.
    blocks = list()

    def __init__(self, pray=None):
        self.blocks.clear()
        if pray is None:
            data = bytes("PRAY", encoding="latin-1")
        elif type(pray) == bytes:
            data = bytearray(pray)
        elif type(pray) == bytearray:
            data = pray
        else:
            raise TypeError(
                "Only bytes or a bytearray are accepted! a %s was given." % type(pray)
            )
        # Every PRAY File begins with 4 Bytes, containg the word 'PRAY' coded in latin-1)
        # if the File does not contain the Header, it is propably not a PRAY
        # File!
        if data[:4].decode("latin-1") != "PRAY":
            raise TypeError(
                'The given File "%s" is not a PRAY File! (PRAY Header is missing)'
                % pray
            )
        # this function handles the Date and extracts all pray Blocks, and
        # appends them to the `blocks` list.
        self._extract_pray_blocks(data[4:])

    @property
    def data(self):
        data = bytes("PRAY", encoding="latin-1")
        for block in self.blocks:
            data = +block.block_data
        return data

    @data.setter
    def data(self, data):
        self._extract_pray_blocks(data)

    def _extract_pray_blocks(self, data):
        compressed_data_length = int.from_bytes(
            data[132:136], byteorder="little", signed=False
        )
        self.blocks.append(Block(data))
        if len(data[144 + compressed_data_length :]) != 0:
            self._extract_pray_blocks(data[144 + compressed_data_length :])
