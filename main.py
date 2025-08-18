from networkguard.components.data_ingestion import DataIngestion
from networkguard.exceptionhandling.exception import NetworkSecurityException
from networkguard.logging.logger import logging
from networkguard.entity.config_entity import DataIngestionConfig,DataValidationConfig,DataTransformationConfig, ModelTrainerConfig
from networkguard.entity.config_entity import TrainingPipelineConfig
import sys
from networkguard.components.data_validation import DataValidation
from networkguard.components.data_transformation import DataTransformation
from networkguard.components.model_trainer import ModelTrainer


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
        
        logging.info("Data Transformation started")
        data_transformation_config=DataTransformationConfig(trainingpipelineconfig)
        data_transformation=DataTransformation(data_validation_artifact,data_transformation_config)
        data_transformation_artifact=data_transformation.initiate_data_transformation()
        logging.info("DataTransformation done")
        print(data_transformation_artifact)
        
        logging.info("Model training Starred")
        model_trainer_config=ModelTrainerConfig(trainingpipelineconfig)
        model_trainer=ModelTrainer(model_trainer_config=model_trainer_config, data_transformation_artifact=data_transformation_artifact)
        model_train_artifact=model_trainer.initiate_model_trainer()
        
        logging.info("Model Training artifact created")
        
    except Exception as e:
           raise NetworkSecurityException(e,sys)