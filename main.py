from networkguard.components.data_ingestion import DataIngestion

from networkguard.exceptionhandling.exception import NetworkSecurityException
from networkguard.logging.logger import logging
from networkguard.entity.config_entity import DataIngestionConfig,DataValidationConfig
from networkguard.entity.config_entity import TrainingPipelineConfig
import sys
from networkguard.components.data_validation import DataValidation

if __name__=='__main__':
    try:
        trainingpipelineconfig=TrainingPipelineConfig()
        data_ingestion_config=DataIngestionConfig(trainingpipelineconfig)
        data_ingestion=DataIngestion(data_ingestion_config)
        logging.info("Initiate the data ingestion")
        dataingestionartifact=data_ingestion.initiate_data_ingestion()
        logging.info("Data ingestion completed")
        print(dataingestionartifact)
        data_validation_config=DataValidationConfig(trainingpipelineconfig)
        data_validation=DataValidation(dataingestionartifact,data_validation_config)
        logging.info("Initiate Date Validation")
        data_validation_artifact=data_validation.initiate_data_validation()
        logging.info("DataValidation Completed")
        print(data_validation_artifact)
        
    except Exception as e:
           raise NetworkSecurityException(e,sys)