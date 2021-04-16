#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import platform
import os

from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict

from polyswarmclient.abstractscanner import AbstractScanner, ScanResult, ScanMode
from polyswarmclient.bidstrategy import BidStrategyBase

import addis_ababa
import yara
import tempfile
import zipfile

# CUSTOMIZE_HERE
# If your engine must call out to a scan engine binary, customize this path to match the location of that backend, e.g.:
# PATH_SCANNER_BINARY = os.getenv(
#     "PS_PATH_SCANNER_BINARY",
#     os.path.join(
#         os.path.dirname(__file__),
#         "..",
#         "..",
#         "pkg",
#         "addis.sh")
#         
#     )

logger = logging.getLogger(__name__)  # Init logger


class BidStrategy(BidStrategyBase):
    """
    Microengine developers may subclass BidStrategyBase to modify default bid logic paramters or implement fully custom bidding (staking) logic.

    BidStrategyBase's default bid() strategy:
    1. averages confidences over all artifacts in the given bounty, arriving at a single value
    2. fits this value on a bid scale, the boundaries of which are set via minimum and maximum multipliers supplied via its constructor

    View the code: https://github.com/polyswarm/polyswarm-client/blob/master/src/polyswarmclient/bidstrategy.py

    NOTE: Assertions for multi-artifact bounties only permit a single bid amount.
    This is a known limitation that will be removed in the near future.
    Soon, a mapping of N bids to N artifacts in a single assertion will be supported.
    Once this is supported, the default bif strategy of producing an average bid across all bounties will be deprecated.
    """

    # CUSTOMIZE BELOW

    # Override BidStrategyBase's:
    # * constructor: to alter the minimum & maximum bid multipliers used in the default bid method
    def __init__(self):
        """
        The absolute minimum bid amount is currently 0.0625 NCT.

        With a min_bid_multiplier of:
        * 8: the floor is set to 0.5 NCT (0.0625 * 8)

        With a max_bid_multiplier:
        * 8: the ceiling is set to 0.5 NCT (0.0625 * 8)

        If min_bid_multiplier < max_bid_multiplier, the floor and ceiling differ.
        Confidence is used to determine where the bid falls in the range.
        """
        super().__init__(min_bid_multiplier=8, max_bid_multiplier=8)

    # Override BidStrategyBase's:
    # * bid() method: to implement fully custom bid logic
    #def bid(self):
        # my custom bid logic


class Scanner(AbstractScanner):
    def __init__(self):
        super(Scanner, self).__init__(ScanMode.SYNC)
        self.addis = Addis()

    async def setup(self):
        """
        Override this method to implement custom setup logic.
        This is run by arbiters and microengines after the Scanner class is instantiated and before any calls to the scan() method.

        Returns:
            status (bool): Did setup complete successfully?
        """
        return await self.addis.setup()

    async def teardown(self):
        """
        Override this method to do any cleanup when the scanner is being shut down.

        This can be called multiple times, due to exception handling restarting the worker/microengine/arbiter
        There is an expectation that calling `setup()` again will put the AbstractScanner implementation back into working order
        """
        await self.addis.teardown()

    def scan_sync(self, guid, artifact_type, content, metadata, chain):
        """
        Args:
            guid (str): GUID of the bounty under analysis, use to track artifacts in the same bounty
            artifact_type (ArtifactType): Artifact type for the bounty
            content (bytes): Content of the artifact to be scan
            metadata (dict): Metadata from polyswarm client about filetype, hash, etc
            chain (str): Chain we are operating on
        Returns:
            ScanResult: Result of this scan
        """
        verdict_metadata = Verdict().set_malware_family('')\
                                    .set_scanner(operating_system=platform.system(),
                                                 architecture=platform.machine(),
                                                 vendor_version='',
                                                 version=addis_ababa.__version__)

        # File Scan
        if artifact_type == ArtifactType.FILE:
            return self.addis.file_scan(content, verdict_metadata)
            

        

        # Not supported artifact
        logger.error('Invalid artifact_type. Skipping bounty.')
        return ScanResult()


class Addis:
    """
    CUSTOMIZE_HERE
        This is where you implement your scanner's logic.
    """
    def __init__(self):
        pass

    async def setup(self):
        """
        Override this method to implement custom setup logic.

        Returns:
            status (bool): Did setup complete successfully?
        """
        # If your participant requires time to, e.g. connect to an external service before it can process requests,
        # check for the availability of the service here. Return True when ready, False if there's an error.
        return True

    async def teardown(self):
        """
        Override this method to implement custom teardown logic.
        """
        # CUSTOMIZE_HERE
        # If your participant leaves long running connections, or uses other long running resources, clean them up here
        # Be aware, setup may be called after teardown due to polyswarm-client's backoff logic
        pass

    def file_scan(self, content, verdict_metadata):
        """
        Implement your File Scan microengine

        Args:
            content (bytes): binary content
            verdict_metadata (Verdict): metadata object

        Returns:
            ScanResult: Result of this scan
        """
        # create basic metasploit rule
        metasploit_rule = """
            rule metasploit 
            {
                meta:
                    description = "This rule detects apps made with metasploit framework"
                    sample = "cb9a217032620c63b85a58dde0f9493f69e4bda1e12b180047407c15ee491b41"

                strings:
                    $a = "*Lcom/metasploit/stage/PayloadTrustManager;"
                    $b = "(com.metasploit.stage.PayloadTrustManager"
                    $c = "Lcom/metasploit/stage/Payload$1;"
                    $d = "Lcom/metasploit/stage/Payload;"

                condition:
                    all of them
            }
            rule metasploit_obsfuscated
            {
                meta:
                    description = "This rule tries to detect apps made with metasploit framework but with the paths changed"

                strings:
                    $a = "currentDir"
                    $b = "path"
                    $c = "timeouts"
                    $d = "sessionExpiry"
                    $e = "commTimeout"
                    $f = "retryTotal"
                    $g = "retryWait"
                    $h = "payloadStart"
                    $i = "readAndRunStage"
                    $j = "runStageFromHTTP"
                    $k = "useFor"
                    

                condition:
                    all of them
                    
            }
        """

        # to simplify thins, create a file from the content that is passed
        # here, we will check if the file is compressed (since apk files are compressed)
        # and do a basic check to see if the compressed file contains classes.dex & AndroidManifest.xml
        # so checks are necessary because our rule operates on Android'a APK file

        is_malicious = False

        temp_file = tempfile.TemporaryFile()
        temp_file.write(content)
        
        if zipfile.is_zipfile(temp_file):

            zip1 = zipfile.ZipFile(temp_file)

            # available files in the container
            files = zip1.namelist()
            print(files)
            for file in files:
                if '.dex' in file:
                    # extract a specific file from zip 
                    logging.info('analyzing classes.dex')
                    f = zip1.open(file, 'r')
                    classes_content = f.read()
                    f.close()
                    rule = yara.compile(source=metasploit_rule)
                    matches = rule.match(data=classes_content)
                    if len(matches) > 0:
                        logging.info('metasploit match found!')
                        # we have a match. Hence, tell polyswarm 
                        # to stake our asserstion with true verdict signaling the sample is malicious
                        is_malicious = True
                        break

        temp_file.close()   
        if is_malicious:
            logging.info('Making an assertion with verdict flag set to false!')
            return ScanResult(bit=True, verdict=True, metadata=verdict_metadata.json())

        # otherwise, we don't particiapte (bit is set to False)
        return ScanResult(bit=False, verdict=False, metadata=metadata.json())

    
