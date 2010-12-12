"""Google Safe Browsing DataStore Interface.
"""

import abc


class DataStoreInterface(object):
    """
    Interface Class for Google Safe Browsing DataStore
    """
    __meta__ = abc.ABCMeta

    # Value is a dict of listname:sblist.List.
    LISTS = 'lists'

    WRKEY = 'wrkey'
    CLIENTKEY = 'clientkey'


    @abc.abstractmethod
    def __init__(self, basefile, create=True):
        """
        Init datastore. Ensure it exists and set up correctly if create=True.
        """


    @abc.abstractmethod
    def Sync(self):
        """
        Update storage. This could be very slow with some database backends.
        Also, it must replace the objects in the database with new copies so
        that existing references to the old objects will no longer update the
        datastore. E.g., you must call GetLists() again after calling this.
        """


    @abc.abstractmethod
    def GetLists(self):
        """
        Return a dict of listname:sblist.List. Changes to this dict and the
        List objects in it are written back to the data store when Sync is
        called.
        """


    @abc.abstractmethod
    def GetWrKey(self):
        pass


    @abc.abstractmethod
    def SetWrKey(self, wrkey):
        pass


    @abc.abstractmethod
    def GetClientKey(self):
        """
        Return unescaped client key.
        """


    @abc.abstractmethod
    def SetClientKey(self, clientkey):
        pass
