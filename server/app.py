from flask import Flask, request, jsonify
from flask_cors import CORS

import utils

app = Flask(__name__)
cors = CORS(app)


@app.route('/event_statistic')
def event_statistic():
    dataType = request.args.get('dataType')
    result = utils.get_event_statistic_by_type(dataType)
    return jsonify(result)


@app.route('/data_valid')
def data_valid():
    result = utils.get_data_valid()
    return jsonify(result)


@app.route('/data_class_stat')
def data_class_stat():
    dataType = request.args.get('dataType')
    result = utils.get_data_class_stat(dataType)
    return jsonify(result)


@app.route('/point')
def data_point_stat():
    stat_type = request.args.get('stat_type')
    result = utils.get_point_statistic(int(stat_type))
    return jsonify(result)


@app.route('/event_predict')
def event_predict():
    idx = request.args.get('idx')
    idx = int(idx)
    result = utils.predict(idx)
    return jsonify(result)


@app.route('/evaluation')
def event_evaluate():
    idx = request.args.get('idx')
    idx = int(idx)
    result = utils.evaluation(idx)
    return result


@app.route('/feature_stat')
def feature_stat():
    feature_type = request.args.get('featureType')
    x, y = utils.get_feature_stat(feature_type)
    return jsonify({
        'x': x,
        'y': y
    })


if __name__ == '__main__':
    app.run()
