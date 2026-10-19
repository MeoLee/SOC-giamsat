"""Independent provenance regressions; synthetic fixtures never establish accuracy."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import prepare_session_data as preparation
from soc_ai.common import read_json, sha256, write_json
import test_local_data as normal_test_helpers
from test_prepare_session_data import fixture


class SessionPreparationReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.manifest=fixture(self.root)

    def test_one_raw_capture_cannot_be_partitioned_between_roles_by_renaming_ids(self):
        data=read_json(self.manifest)
        contents=[]; offsets={}
        # Each role selects different observations from one physical EVE file.
        # Labels and their line hashes remain correct, and IDs are all distinct.
        for session in data['sessions']:
            source=next(entry for entry in session['evidence_files'] if entry['kind']=='raw_eve')
            offsets[session['id']]=len(contents)
            contents.extend((self.root/source['path']).read_bytes().splitlines(keepends=True))
        shared=self.root/'one-physical-capture.jsonl'; shared.write_bytes(b''.join(contents))
        for session in data['sessions']:
            source=next(entry for entry in session['evidence_files'] if entry['kind']=='raw_eve')
            source.update(path=shared.name,sha256=sha256(shared))
            label_path=self.root/session['records']
            labels=[json.loads(line) for line in label_path.read_text().splitlines()]
            for item in labels: item['raw_ref']['line']+=offsets[session['id']]
            label_path.write_text(''.join(json.dumps(item)+'\n' for item in labels))
            session['sha256']=sha256(label_path)
        write_json(self.manifest,data)
        with self.assertRaises(ValueError): preparation.run(self.manifest,self.root/'prepared')

    def test_synthetic_base_marker_survives_mixing_with_non_synthetic_manifest(self):
        helper=normal_test_helpers.LocalDataTests(); helper.root=self.root
        base=helper.base()
        report=read_json(base/'report.json'); report['synthetic_fixture']=True
        write_json(base/'report.json',report)
        data=read_json(self.manifest); data['synthetic']=False; write_json(self.manifest,data)
        # The incoming declaration cannot erase the stronger known base marker.
        # All data in this regression remains synthetic, regardless of the flag.
        result=preparation.run(self.manifest,self.root/'prepared',base)
        self.assertTrue(result['synthetic_fixture'])

    def test_known_synthetic_row_marker_cannot_be_erased_by_real_root_flag(self):
        data=read_json(self.manifest); data['synthetic']=False
        session=data['sessions'][0]; path=self.root/session['records']
        rows=[json.loads(line) for line in path.read_text().splitlines()]
        rows[0]['synthetic']=True
        path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        session['sha256']=sha256(path); write_json(self.manifest,data)
        result=preparation.run(self.manifest,self.root/'prepared')
        self.assertTrue(result['synthetic_fixture'])

    def test_imported_evidence_labels_and_report_are_rechecked_after_iteration(self):
        helper=normal_test_helpers.LocalDataTests(); helper.root=self.root
        for index,target in enumerate(('auth','labels','report')):
            with self.subTest(target=target):
                directory,report=helper.imported('review-import-'+str(index),'train',port=55001+index)
                labels=directory/'labeled-flows.jsonl'; report_path=directory/'report.json'
                session={'id':report['session_id'],'role':'train',
                         'capture_session_id':'review-physical-'+str(index),
                         'import_directory':str(directory.relative_to(self.root)),
                         'report_sha256':sha256(report_path)}
                original_rows=preparation.rows; mutated=[]

                def mutate_after_hash_checks(path):
                    if Path(path)==labels and not mutated:
                        mutated.append(True)
                        if target=='auth':
                            Path(report['inputs']['auth']['path']).write_text('Changed after initial hash check\n')
                        elif target=='labels':
                            item=json.loads(labels.read_text()); item['flow']['bytes_toserver']+=1
                            labels.write_text(json.dumps(item)+'\n')
                        else:
                            changed=dict(report,complete=False); write_json(report_path,changed)
                    yield from original_rows(path)

                with patch.object(preparation,'rows',mutate_after_hash_checks):
                    with self.assertRaises(ValueError):
                        list(preparation.imported_records(self.root,session))
                self.assertTrue(mutated,'Rejection must occur after the controlled mid-read mutation')


if __name__=='__main__': unittest.main()
