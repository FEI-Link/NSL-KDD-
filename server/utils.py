import pandas as pd
import json
from sklearn.ensemble import RandomForestClassifier
from collections import Counter


def get_event_type_name_map():
    with open('攻击事件.txt', 'r', encoding='utf-8') as f:
        data = f.read().split()
        data = list(map(lambda x: x.replace('（', '-').replace('）', '').split('-'), data))
        data = dict(data)
        return data


def get_event_statistic_by_type(data_type):
    event_type_name_map = get_event_type_name_map()

    if data_type == 'train':
        path = 'KDDTrain+.txt'
    else:
        path = 'KDDTest+.txt'

    table = pd.read_table(path, header=None, delimiter=',')
    data_count = table[41].value_counts()
    data_dict = dict(data_count)
    result = []
    total = sum(data_dict.values())
    for e in data_dict:
        result.append({'type': e, 'name': event_type_name_map.get(e), 'amount': int(data_dict[e]),
                       'percent': float(round(data_dict[e] / total * 100, 4))})
    return result


def get_data_valid():
    with open('event.json', 'r') as f:
        event_class = dict(json.load(f))
    train_stat = get_event_statistic_by_type('train')
    test_stat = get_event_statistic_by_type('test')
    result = []
    train_result = {'dataSetName': 'KDDTrain+.txt', 'total': len(train_stat), 'Normal': 0, 'DoS': 0, 'Probe': 0,
                    'U2R': 0, 'R2L': 0}
    for e in train_stat:
        for k in event_class.keys():
            if e.get('type') in event_class.get(k):
                train_result[k] = train_result.get(k) + e.get('amount')
                train_result['total'] += e.get('amount')
    test_result = {'dataSetName': 'KDDTest+.txt', 'total': len(test_stat), 'Normal': 0, 'DoS': 0, 'Probe': 0, 'U2R': 0,
                   'R2L': 0}
    for e in test_stat:
        for k in event_class.keys():
            if e.get('type') in event_class.get(k):
                test_result[k] = test_result.get(k) + e.get('amount')
                test_result['total'] += e.get('amount')
    for k in event_class.keys():
        train_result[k] = str(train_result[k]) + '（' + str(
            round(train_result[k] / train_result['total'] * 100, 2)) + '%）'
        test_result[k] = str(test_result[k]) + '（' + str(round(test_result[k] / test_result['total'] * 100, 2)) + '%）'
    result.append(train_result)
    result.append(test_result)
    return result


def get_data_class_stat(data_type):
    with open('event.json', 'r') as f:
        event_class = dict(json.load(f))
    if data_type == 'train':
        stat = get_event_statistic_by_type('train')
    else:
        stat = get_event_statistic_by_type('test')
    result = {'Normal': 0, 'DoS': 0, 'Probe': 0, 'U2R': 0, 'R2L': 0}
    for e in stat:
        for k in event_class.keys():
            if e.get('type') in event_class.get(k):
                result[k] = result.get(k) + e.get('amount')
    count = []
    for k in result:
        count.append({'name': k, 'value': result.get(k)})
    return count


def get_point_statistic(stat_type):
    with open('一万个IP地址.txt', 'r') as f:
        ips = f.read().split()
    table = pd.read_table('KDDTrain+.txt', header=None, delimiter=',')
    data = table.head(10000)
    data['ip'] = ips
    data = data.sort_values(stat_type, ascending=False)
    data = data.head(20)
    ips = data['ip']
    ip_bytes = data[stat_type]
    result = zip(ips, ip_bytes)
    result = list(map(lambda x: {'ip': x[0], 'bytes': x[1]}, result))
    return result


def get_feature_stat(feature_type):
    x, y = [], []
    if feature_type == 'protocol':
        stat_list = train_table[1].values.tolist()
    else:
        stat_list = train_table[3].values.tolist()
    res = Counter(stat_list)
    for k in res:
        x.append(k)
        y.append(res.get(k))
    return x, y


def predict(idx):
    if idx == 1:
        test_path = 'KDDTest+.txt'
    else:
        test_path = 'KDDTest-21.txt'

    test_table = pd.read_table(test_path, header=None, delimiter=',')
    y_test = test_table[41]
    x_test = test_table.drop(columns=[1, 2, 3, 41])

    y_pred = clf.predict(x_test)
    counter = Counter(y_pred)
    total = sum(counter.values())
    res = []
    for e in counter:
        res.append({'event_type': e, 'num': counter[e], 'ratio': round(counter[e] / total * 100, 2)})
    return res


def evaluation(idx):
    res = predict(idx)
    ratio = 0
    for e in res:
        if e['event_type'] == 'normal':
            ratio = e['ratio']
            break
    if ratio > 80:
        return '1'
    elif ratio > 63:
        return '2'
    else:
        return '3'


train_table = pd.read_table('KDDTrain+.txt', header=None, delimiter=',')
y_train = train_table[41]
x_train = train_table.drop(columns=[1, 2, 3, 41])
clf = RandomForestClassifier()
clf.fit(x_train, y_train)
