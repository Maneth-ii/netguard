This directory is empty until you run:

    python3 -m ml.train_model

That trains an IsolationForest on your local scikit-learn version and saves
isolation_forest.joblib + scaler.joblib here. Training locally (rather than
shipping a pre-trained pickle) avoids scikit-learn version-mismatch warnings
between the environment the model was trained in and the one running it.
