#include <libcryptosec/DynamicEngine.h>

DynamicEngine::DynamicEngine(std::string &enginePath) : Engine(NULL)
{
	this->engine = ENGINE_by_id("dynamic");
	if (!this->engine)
	{
		throw EngineException(EngineException::DYNAMIC_ENGINE_UNAVAILABLE, "DynamicEngine::DynamicEngine");
	}
	try
	{
		std::string key;
		key = "SO_PATH";
		this->setCommand(key, enginePath);
		key = "LOAD";
		this->setCommand(key);
	}
	catch (EngineException &ex)
	{
		ENGINE_free(this->engine);
		this->engine = NULL;
		throw EngineException(EngineException::LOAD_ENGINE_FAILED, "DynamicEngine::DynamicEngine", ex.getDetails());
	}
}

DynamicEngine::DynamicEngine(std::string &enginePath, std::string &engineId) : Engine(NULL)
{
	this->engine = ENGINE_by_id("dynamic");
	if (!this->engine)
	{
		throw EngineException(EngineException::DYNAMIC_ENGINE_UNAVAILABLE, "DynamicEngine::DynamicEngine");
	}
	try
	{
		std::string key;
		key = "SO_PATH";
		this->setCommand(key, enginePath);
		key = "ID";
		this->setCommand(key, engineId);
		key = "LOAD";
		this->setCommand(key);
	}
	catch (EngineException &ex)
	{
		ENGINE_free(this->engine);
		this->engine = NULL;
		throw EngineException(EngineException::LOAD_ENGINE_FAILED, "DynamicEngine::DynamicEngine", ex.getDetails());
	}
}

DynamicEngine::DynamicEngine(std::string &enginePath, std::string &engineId, std::vector<std::pair<std::string, std::string> > &extraCommands) : Engine(NULL)
{
	ENGINE_load_dynamic();
	this->engine = ENGINE_by_id("dynamic");
	if (!this->engine)
	{
		throw EngineException(EngineException::DYNAMIC_ENGINE_UNAVAILABLE, "DynamicEngine::DynamicEngine");
	}
	try
	{
		std::string key, value;
		key = "SO_PATH";
		this->setCommand(key, enginePath);
		key = "ID";
		this->setCommand(key, engineId);
		key = "LOAD";
		this->setCommand(key);
		for(unsigned int i=0;i<extraCommands.size();i++) {
			key = extraCommands[i].first;
			value = extraCommands[i].second;
			this->setCommand(key, value);
		}
	}
	catch (EngineException &ex)
	{
		ENGINE_free(this->engine);
		this->engine = NULL;
		throw EngineException(EngineException::LOAD_ENGINE_FAILED, "DynamicEngine::DynamicEngine", ex.getDetails());
	}
}


DynamicEngine::~DynamicEngine()
{
}

void DynamicEngine::addToEnginesList()
{
	if (!(ENGINE_add(this->engine)))
	{
		throw EngineException(EngineException::ADD_ENGINE_TO_LIST, "DynamicEngine::addToEnginesList");
	}
}

void DynamicEngine::removeFromEnginesList()
{
	if (!(ENGINE_remove(this->engine)))
	{
		throw EngineException(EngineException::REMOVE_ENGINE_FROM_LIST, "DynamicEngine::removeFromEnginesList");
	}
}
