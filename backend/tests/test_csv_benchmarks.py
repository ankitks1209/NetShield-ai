import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

ML = Path(__file__).resolve().parents[2]/'ml'
sys.path.insert(0,str(ML))
spec=importlib.util.spec_from_file_location('csv_benchmarks',ML/'train_csv_benchmarks.py')
benchmarks=importlib.util.module_from_spec(spec);spec.loader.exec_module(benchmarks)


class CSVBenchmarkTests(unittest.TestCase):
    def test_unsw_reader_excludes_identifiers_and_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory,'rows.csv')
            pd.DataFrame([{'id':123,'dur':1,'proto':'tcp','service':'http','state':'FIN',
                           'spkts':4,'label':1,'attack_cat':'Exploits'}]).to_csv(path,index=False)
            features,labels,_,categorical=benchmarks.read_unsw(path)
            self.assertTrue({'id','label','attack_cat'}.isdisjoint(features.columns))
            self.assertEqual(labels.tolist(),['Exploits'])
            self.assertEqual(categorical,['proto','service','state'])

    def test_cicids_reservoir_is_bounded_repeatable_and_reports_invalid_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            rows=pd.DataFrame({'Destination Port':np.arange(100),'Flow Duration':np.arange(100)/10,
                               'Label':['BENIGN']*80+['Attack']*20})
            rows.loc[0,'Flow Duration']=np.inf
            rows.to_csv(Path(directory,'day.csv'),index=False)
            first,labels,info,_=benchmarks.read_cicids(directory,10)
            second,second_labels,_,_=benchmarks.read_cicids(directory,10)
            pd.testing.assert_frame_equal(first,second);pd.testing.assert_series_equal(labels,second_labels)
            self.assertEqual(labels.value_counts().to_dict(),{'Attack':10,'Normal':10})
            self.assertEqual(info['invalid_rows']['day.csv'],1)
            self.assertEqual(info['source_class_support']['Normal'],79)

    def test_official_holdout_is_kept_separate_and_model_is_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            data=root/'UNSW-NB15/Training and Testing Sets';data.mkdir(parents=True)
            def fixture(offset):
                return pd.DataFrame([{'id':i,'dur':offset+i/100,'proto':'tcp','service':'http','state':'FIN',
                    'spkts':i+2,'label':i%2,'attack_cat':'Exploits' if i%2 else 'Normal'} for i in range(100)])
            fixture(1).to_csv(data/'UNSW_NB15_training-set.csv',index=False)
            fixture(2).to_csv(data/'UNSW_NB15_testing-set.csv',index=False)
            with patch.object(benchmarks,'PARAMETERS',{**benchmarks.PARAMETERS,'n_estimators':3}):
                report=benchmarks.run('unsw-nb15',root/'output',raw_root=root)
            self.assertEqual(report['split']['holdout_rows'],100)
            self.assertEqual(report['split']['shared_fit_validation_groups'],0)
            self.assertNotEqual(report['provenance']['train_sha256'],report['provenance']['holdout_sha256'])
            self.assertTrue((root/'output/model.joblib').is_file())
            self.assertFalse(report['live_approved'])
