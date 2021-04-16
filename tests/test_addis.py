#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import pytest
import sys

from malwarerepoclient.client import DummyMalwareRepoClient
from addis_ababa import Scanner
from polyswarmartifact import ArtifactType


@pytest.yield_fixture(scope='session')
def event_loop():
    """
    To enable Windows engines to support subprocesses in asyncio, they need to use the ProactorEventLoop.

    When the engine is running via polyswarm-client, this is handled by polyswarm-client.
    But when using pytest, you do not run the engine via polyswarm-client, so you have to change the loop in a fixture.

    ref: https://docs.python.org/3/library/asyncio-eventloops.html

    :return: event loop object
    """
    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


@pytest.mark.asyncio
async def test_scan_random_mal_not():
    """
    1. Run scanner against one malicious file (EICAR) and one non-malicious file.
    """
    scanner = Scanner()
    async with scanner:

        ###
        ### File artifacts
        ###

        for t in [True, False]:
            mal_md, mal_content = DummyMalwareRepoClient()\
                                  .get_random_file(malicious_filter=t)
            result = await scanner.scan(guid='nocare',
                                        artifact_type=ArtifactType.FILE,
                                        content=ArtifactType.FILE.decode_content(mal_content),
                                        metadata=None,
                                        chain='home')
            assert result.bit
            assert result.verdict == t
@pytest.mark.asyncio
async def test_setup_teardown_multiple_times():
    scanner = Scanner()
    await scanner.setup()
    await scanner.setup()
    await scanner.teardown()
    await scanner.teardown()
    await scanner.setup()