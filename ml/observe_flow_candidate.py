"""Score saved Zeek connection logs in shadow mode and export aggregates only."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from flow_candidate import FlowCandidate
from zeek_reader import ZeekLogReader


def observe(model_dir, conn_log, output):
    if Path(output).resolve()==Path(conn_log).resolve():
        raise ValueError('The aggregate report must not replace the input connection log')
    model=FlowCandidate();model.load(model_dir,'shadow')
    if not model.status()['loaded']: raise ValueError(model.status()['error'])
    reader=ZeekLogReader(conn_log)
    counts,labels,reasons=Counter(),Counter(),Counter()
    try:
        while True:
            events=reader.poll()
            if not events: break
            for event in events:
                if event.kind=='error': counts['malformed_lines']+=1
                if event.kind!='flow': continue
                counts['flows']+=1
                result=model.score(event.flow)
                counts[result['status']]+=1
                if result['status']=='shadow': labels[result['candidate_label']]+=1
                if result.get('reason'): reasons[result['reason']]+=1
    finally: reader.close()
    result={'observed_at':datetime.now(timezone.utc).isoformat(),'model_version':model.status()['model_version'],
            'log_sha256':hashlib.sha256(Path(conn_log).read_bytes()).hexdigest(),
            'counts':dict(counts),'candidate_labels':dict(labels),'abstention_reasons':dict(reasons),
            'live_approved':False,'incidents_created':0,
            'scope':'Unlabeled shadow observation. Candidate labels are not ground truth, live verdicts, precision, recall, or false-positive measurements.'}
    Path(output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-dir',type=Path,required=True)
    parser.add_argument('--conn-log',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();observe(args.model_dir,args.conn_log,args.output)
