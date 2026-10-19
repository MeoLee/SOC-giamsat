import concurrent.futures
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from soc_ai.common import read_json,write_json
from soc_ai.fileio import open_shared_read,replace_with_retry
from soc_ai.workflow import Workflow


def locked_file_error():
    error=PermissionError('simulated Windows file lock')
    error.winerror=32
    return error


class FileIOTests(unittest.TestCase):
    def test_transient_windows_lock_retries_then_commits(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'status.json'; write_json(path,{'epoch':18})
            real_replace=os.replace; calls=[]
            def transient(source,destination):
                calls.append(str(source))
                if len(calls)<=2: raise locked_file_error()
                return real_replace(source,destination)
            with mock.patch('soc_ai.fileio.os.replace',side_effect=transient),mock.patch('soc_ai.fileio.time.sleep'):
                write_json(path,{'epoch':19})
            self.assertEqual(read_json(path),{'epoch':19})
            self.assertEqual(len(calls),3)
            self.assertEqual(list(Path(d).glob('*.tmp')),[])

    def test_failed_replace_preserves_previous_file(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'model.json'; write_json(path,{'complete':False})
            with mock.patch('soc_ai.fileio.os.replace',side_effect=OSError('disk failure')):
                with self.assertRaises(OSError): write_json(path,{'complete':True})
            self.assertEqual(read_json(path),{'complete':False})
            self.assertEqual(list(Path(d).glob('*.tmp')),[])

    def test_retry_window_is_bounded(self):
        with mock.patch('soc_ai.fileio.os.replace',side_effect=locked_file_error()) as replace:
            with self.assertRaises(PermissionError): replace_with_retry('src','dest',timeout=0)
            self.assertEqual(replace.call_count,1)

    def test_concurrent_writes_always_publish_complete_json(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'status.json'; write_json(path,{'writer':-1,'text':'x'*4000})
            def worker(number):
                write_json(path,{'writer':number,'text':'x'*4000})
                self.assertEqual(len(read_json(path)['text']),4000)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(worker,range(80)))
            self.assertIn(read_json(path)['writer'],range(80))
            self.assertEqual(list(Path(d).glob('*.tmp')),[])

    def test_status_lock_does_not_abort_workflow_and_can_recover(self):
        with tempfile.TemporaryDirectory() as d:
            workflow=Workflow(d,'train'); console=io.StringIO()
            with mock.patch('soc_ai.workflow.write_json',side_effect=locked_file_error()),contextlib.redirect_stdout(console):
                workflow.update('train','Training epoch 19/20',epoch=19)
                workflow.update('validation','Validating epoch 19')
                workflow.finish('paused','Checkpoint saved')
            self.assertEqual(console.getvalue().count('WARNING:'),1)
            workflow.finish('paused','Checkpoint saved')
            state=read_json(Path(d)/'status.json')
            self.assertEqual(state['status'],'paused')
            self.assertEqual(state['epoch'],19)

    def test_snapshot_releases_disk_file_before_caller_closes_stream(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'status.json'; write_json(path,{'epoch':18})
            with open_shared_read(path) as snapshot:
                self.assertIsInstance(snapshot,io.BytesIO)
                moved=path.with_name('old.json')
                path.rename(moved)
                write_json(path,{'epoch':19})
                self.assertIn(b'18',snapshot.read())
                self.assertEqual(read_json(path),{'epoch':19})

    @unittest.skipUnless(os.name=='nt','Windows atomic replacement integration')
    def test_windows_reader_does_not_block_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'status.json'; write_json(path,{'epoch':18})
            with open_shared_read(path) as old_snapshot:
                write_json(path,{'epoch':19})
                self.assertIn(b'18',old_snapshot.read())
            self.assertEqual(read_json(path),{'epoch':19})

    @unittest.skipUnless(os.name=='nt','Windows missing path integration')
    def test_windows_missing_file_preserves_os_error(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileNotFoundError): open_shared_read(Path(d)/'not-created.json')


if __name__=='__main__': unittest.main()
