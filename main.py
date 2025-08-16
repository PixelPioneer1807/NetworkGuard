from networkguard.components.data_ingestion import DataIngestion

from networkguard.exceptionhandling.exception import NetworkSecurityException
from networkguard.logging.logger import logging
from networkguard.entity.config_entity import DataIngestionConfig
from networkguard.entity.config_entity import TrainingPipelineConfig
import sys


if __name__=='__main__':
    try:
        trainingpipelineconfig=TrainingPipelineConfig()
        data_ingestion_config=DataIngestionConfig(trainingpipelineconfig)
        data_ingestion=DataIngestion(data_ingestion_config)
        logging.info("Initiate the data ingestion")
        dataingestionartifact=data_ingestion.initiate_data_ingestion()
        print(dataingestionartifact)
    except Exception as e:
           raise NetworkSecurityException(e,sys)