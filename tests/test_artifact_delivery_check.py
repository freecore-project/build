import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import tarfile
import unittest
from unittest import mock

import test_freecore_r2_delivery as fixtures


delivery = fixtures.delivery


class ArtifactDeliveryCheckTests(fixtures.FixtureMixin, unittest.TestCase):
    def fail_apply(self, source, plan):
        store = fixtures.RecordingStore(self.root / 'store')
        journal = self.root / 'journal.json'
        with self.assertRaises(delivery.DeliveryError) as raised:
            delivery.apply_plan(plan, source, store, journal, plan['plan_sha256'])
        self.assertEqual(store.puts, [])
        self.assertFalse(journal.exists())
        return str(raised.exception)

    def report_checker(self, report, exit_code=0, before=''):
        checker = self.root / 'report-checker'
        checker.write_text('#!' + sys.executable + '\n' + before
                           + '\nimport sys\nsys.stdout.write(' + repr(report)
                           + ')\nsys.exit(' + str(exit_code) + ')\n')
        checker.chmod(0o700)
        os.environ['FREECORE_ARTIFACT_CHECKER'] = str(checker)

    def test_missing_relative_unavailable_checker_blocks_plan_and_apply_without_writes(self):
        source, plan = self.update_plan()
        for setting in ('', './checker', str(self.root / 'missing')):
            with self.subTest(setting=setting), mock.patch.dict(os.environ, {'FREECORE_ARTIFACT_CHECKER': setting}):
                self.fail_apply(source, plan)
                with self.assertRaises(delivery.DeliveryError):
                    delivery.update_plan(source, fixtures.SOURCE_ID, 'freecore-updates',
                                         'updates.freecore.org', fixtures.GENERATED_AT)

    def test_invalid_incomplete_finding_wrong_identity_and_failed_reports_fail_closed(self):
        source, plan = self.update_plan()
        obj = next(obj for obj in plan['objects'] if obj['key'].startswith('FreeCORE/Packages/'))
        clean = {'schema_version': 1, 'package': 'fixture', 'sha256': obj['sha256'],
                 'size': obj['size'], 'members_scanned': 1, 'files_scanned': 1,
                 'decoded_streams': 0, 'bytes_scanned': 1, 'findings': [],
                 'incomplete': [], 'limitation': 'Fixture protocol report.'}
        cases = [('not json', 0), ('{}', 0), (json.dumps(clean), 1),
                 (json.dumps(clean)[:-1] + ',"sha256":"' + obj['sha256'] + '"}', 0)]
        for changes in ({'findings': [{'category': 'private'}]}, {'incomplete': ['unsupported']},
                        {'sha256': '0' * 64}, {'size': obj['size'] + 1}, {'schema_version': True},
                        {'files_scanned': -1}, {'findings': None}, {'extra': 'ignored?'}):
            cases.append((json.dumps({**clean, **changes}), 0))
        for report, exit_code in cases:
            with self.subTest(report=report, exit_code=exit_code):
                self.report_checker(report, exit_code)
                message = self.fail_apply(source, plan)
                self.assertNotIn(report, message)

    def test_delta_is_checked_even_when_destination_objects_already_exist(self):
        source, plan = self.update_plan()
        store = fixtures.RecordingStore(self.root / 'store')
        journal = self.root / 'journal.json'
        delivery.apply_plan(plan, source, store, journal, plan['plan_sha256'])
        original_journal = journal.read_bytes()
        store.puts.clear()
        checker = Path(os.environ['FREECORE_ARTIFACT_CHECKER'])
        code = checker.read_text().replace("data = path.read_bytes()", "data = path.read_bytes()\nif '-0.9-1.0' in path.name: sys.exit(1)")
        checker.write_text(code)
        with self.assertRaises(delivery.DeliveryError):
            delivery.apply_plan(plan, source, store, journal, plan['plan_sha256'])
        self.assertEqual(store.puts, [])
        self.assertEqual(journal.read_bytes(), original_journal)

    def test_changed_input_during_checker_is_rejected_before_writes(self):
        source, plan = self.update_plan()
        checker = Path(os.environ['FREECORE_ARTIFACT_CHECKER'])
        checker.write_text(checker.read_text() + "\npath.write_bytes(data + b'changed')\n")
        self.assertIn('changed during', self.fail_apply(source, plan))

    def test_checker_cannot_come_from_plan_fields(self):
        source, plan = self.update_plan()
        changed = copy.deepcopy(plan)
        changed['artifact_checker'] = '/operator-executable'
        changed = delivery.seal_plan(changed)
        self.fail_apply(source, changed)
        self.assertNotIn('FREECORE_ARTIFACT_CHECKER', json.dumps(plan))

    def test_real_scanner_clean_plan_apply_and_dirty_delta_interoperate(self):
        gate = os.environ.get('FREECORE_ARTIFACT_GATE_TEST_TOOL')
        if not gate:
            self.skipTest('set FREECORE_ARTIFACT_GATE_TEST_TOOL to the reviewed private scanner')
        source, previous = self.make_update_source()
        manifest_path = (source / delivery.UPDATE_TRAIN / 'LATEST').resolve()
        manifest = json.loads(manifest_path.read_text())
        package = manifest['Packages'][0]
        for filename, entry in (('base-os-1.0.tgz', package),
                                ('base-os-0.9-1.0.tgz', package['Upgrades'][0])):
            path = source / 'Packages' / filename
            with tarfile.open(path, 'w:gz') as archive:
                fixtures.add_tar_member(archive, 'etc/fixture', b'clean public package')
            entry.update(Checksum=hashlib.sha256(path.read_bytes()).hexdigest(), FileSize=path.stat().st_size)
        fixtures.write_json(manifest_path, manifest)
        checker = self.root / 'real-checker'
        checker.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' '
                           + shlex.quote(str(Path(gate).resolve())) + ' "$@"\n')
        checker.chmod(0o700)
        os.environ['FREECORE_ARTIFACT_CHECKER'] = str(checker)
        kwargs = dict(source_root=source, source_identity=fixtures.SOURCE_ID,
                      destination_bucket='freecore-updates', requested_host='updates.freecore.org',
                      generated_at=fixtures.GENERATED_AT, previous_state=previous)
        plan = delivery.update_plan(**kwargs)
        store = fixtures.RecordingStore(self.root / 'store')
        delivery.apply_plan(plan, source, store, self.root / 'clean-journal', plan['plan_sha256'])
        self.assertEqual(len(store.puts), len(plan['objects']))
        # Unsupported nested coverage fails with the real checker, without
        # putting private infrastructure literals into public build fixtures.
        delta = source / 'Packages/base-os-0.9-1.0.tgz'
        with tarfile.open(delta, 'w:gz') as archive:
            fixtures.add_tar_member(archive, 'nested.zip', b'PK\x03\x04fixture')
        digest, size = hashlib.sha256(delta.read_bytes()).hexdigest(), delta.stat().st_size
        package['Upgrades'][0].update(Checksum=digest, FileSize=size)
        fixtures.write_json(manifest_path, manifest)
        with self.assertRaises(delivery.DeliveryError):
            delivery.update_plan(**kwargs)
        dirty = copy.deepcopy(plan)
        for obj in dirty['objects']:
            if obj['source_path'] == 'Packages/base-os-0.9-1.0.tgz':
                obj.update(sha256=digest, size=size)
        self.fail_apply(source, delivery.seal_plan(dirty))

    def test_real_scanner_private_fixture_blocks_before_writes(self):
        gate = os.environ.get('FREECORE_ARTIFACT_GATE_TEST_TOOL')
        residue = os.environ.get('FREECORE_ARTIFACT_GATE_TEST_RESIDUE')
        if not gate or not residue:
            self.skipTest('set private scanner and residue fixture environment variables')
        source, plan = self.update_plan()
        obj = next(obj for obj in plan['objects'] if '-0.9-1.0.tgz' in obj['key'])
        delta = source / obj['source_path']
        with tarfile.open(delta, 'w:gz') as archive:
            fixtures.add_tar_member(archive, 'var/db/fixture', residue.encode('utf-8'))
        obj.update(sha256=hashlib.sha256(delta.read_bytes()).hexdigest(), size=delta.stat().st_size)
        checker = self.root / 'real-private-fixture-checker'
        checker.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' '
                           + shlex.quote(str(Path(gate).resolve())) + ' "$@"\n')
        checker.chmod(0o700)
        os.environ['FREECORE_ARTIFACT_CHECKER'] = str(checker)
        result = fixtures.subprocess.run([str(checker), '--package', str(delta),
                                          '--sha256', obj['sha256'], '--json'],
                                         capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertTrue(report['findings'])
        self.assertEqual(report['incomplete'], [])
        message = self.fail_apply(source, delivery.seal_plan(plan))
        self.assertNotIn(residue, message)


if __name__ == '__main__':
    unittest.main()
