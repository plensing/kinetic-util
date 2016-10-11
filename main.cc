#include <kinetic/kinetic.h>
#include <iostream>
#include <iomanip>
#include <set>

using std::string;

enum class OpType
{
  list, remove, count, help, scan, optimize
};

struct Configuration
{
  kinetic::ConnectionOptions connectionOptions;
  string start_key;
  string end_key;
  std::set<OpType> operations;
};

const struct Configuration DEFAULT_CONFIGURATION{
    {"localhost", 8123, false, 1, "asdfasdf"},
    "!", "~"
};

bool parse(int argc, char** argv, Configuration& config)
{
  for (int i = 1; i < argc; i++) {
    if (strcmp("-pwd", argv[i]) == 0) {
      config.connectionOptions.hmac_key = argv[i + 1];
    }
    if (strcmp("-id", argv[i]) == 0) {
      config.connectionOptions.user_id = atoi(argv[i + 1]);
    }
    if (strcmp("-host", argv[i]) == 0) {
      config.connectionOptions.host = argv[i + 1];
    }
    if (strcmp("-port", argv[i]) == 0) {
      config.connectionOptions.port = atoi(argv[i + 1]);
    }
    if (strcmp("-start_key", argv[i]) == 0) {
      config.start_key = argv[i + 1];
    }
    if (strcmp("-end_key", argv[i]) == 0) {
      config.end_key = argv[i + 1];
    }
    if (strcmp("-l", argv[i]) == 0) {
      config.operations.insert(OpType::list);
    }
    if (strcmp("-d", argv[i]) == 0) {
      config.operations.insert(OpType::remove);
    }
    if (strcmp("-c", argv[i]) == 0) {
      config.operations.insert(OpType::count);
    }
    if (strcmp("-h", argv[i]) == 0) {
      config.operations.insert(OpType::help);
    }
    if (strcmp("-s", argv[i]) == 0) {
      config.operations.insert(OpType::scan);
    }
    if (strcmp("-o", argv[i]) == 0) {
      config.operations.insert(OpType::optimize);
    }
  }

  return !config.operations.empty();
}

void print_help()
{
  std::cout << std::endl;
  std::cout
      << "Usage: ./util [-host string] [-port int] [-id int] [-pwd string] [-start_key string] [-end_key string] [-c] [-d] [-l] [-s] [-o]"
      << std::endl;
  std::cout << "   key based operations: count, delete, list, scan" << std::endl;
  std::cout << "   device based operations: optimize" << std::endl;
}

std::string algotostring(std::unique_ptr<kinetic::KineticRecord>& record)
{
  if (!record) {
    return "N/A";
  }
  switch (record->algorithm()) {
    case kinetic::Command_Algorithm::Command_Algorithm_CRC32:
      return "CRC32";
    case kinetic::Command_Algorithm::Command_Algorithm_CRC64:
      return "CRC64";
    case kinetic::Command_Algorithm::Command_Algorithm_SHA1:
      return "SHA1";
    case kinetic::Command_Algorithm::Command_Algorithm_SHA2:
      return "SHA2";
    case kinetic::Command_Algorithm::Command_Algorithm_SHA3:
      return "SHA3";
    default:
      return "INVALID";
  }
}

void keybased_operation(const Configuration& config, std::shared_ptr<kinetic::ThreadsafeBlockingKineticConnection> con)
{

  if (config.operations.count(OpType::list)) {
    std::cout << std::left << std::setw(80) << std::setfill('-') << "KEY"
              << std::right << std::setw(12) << "VALUE SIZE"
              << std::setw(7) << "TTYPE"
              << std::setw(6) << "TSIZE"
              << std::setw(4) << "" << std::left << "VERSION" << std::endl;
  }

  std::unique_ptr<std::vector<string>> keys;
  if (!con->GetKeyRange(config.start_key, true, config.end_key, true, false, 100, keys).ok()) {
    std::cout << "GetKeyRange failed." << std::endl;
  }

  int keycount = 0;
  while (keys && keys->begin() != keys->end()) {
    keycount += keys->size();

    if (config.operations.count(OpType::list)) {
      for (auto it = keys->begin(); it != keys->end(); it++) {
        std::unique_ptr<kinetic::KineticRecord> r;
        if (!con->Get(*it, r).ok()) {
          std::cout << "Get failed for key " << *it << std::endl;
        } else {
          std::cout << std::left << std::setw(80) << *it
                    << std::right << std::setw(12) << (r && r->value() ? std::to_string(r->value()->size()) : "N/A")
                    << std::setw(7) << algotostring(r)
                    << std::setw(6) << (r && r->tag() ? std::to_string(r->tag()->size()) : "N/A")
                    << std::setw(4) << "" << std::left << (r && r->version() ? *(r->version()) : "N/A")
                    << std::endl;
        }
      }
    }

    if (config.operations.count(OpType::remove)) {
      for (auto it = keys->begin(); it != keys->end(); it++) {
        if (!con->Delete((*it), "", kinetic::WriteMode::IGNORE_VERSION).ok()) {
          std::cout << "Failed deleting key " << (*it) << std::endl;
        }
      }
    }

    if (!con->GetKeyRange(keys->back(), false, config.end_key, true, false, 100, keys).ok()) {
      std::cout << "GetKeyRange failed." << std::endl;
    }
  }

  if (config.operations.count(OpType::count)) {
    std::cout << "Processed Keys: " << keycount << std::endl;
  }
  if (config.operations.count(OpType::remove)) {
    std::cout << "Deletion Completed." << std::endl;
  }
}

int main(int argc, char** argv)
{
  Configuration config = DEFAULT_CONFIGURATION;
  if (!parse(argc, argv, config)) {
    std::cout << "No valid operations to execute. Use -h for help." << std::endl;
    return EXIT_FAILURE;
  }

  if (config.operations.erase(OpType::help)) {
    print_help();
    if (config.operations.empty()) {
      return EXIT_SUCCESS;
    }
  }

  std::shared_ptr<kinetic::ThreadsafeBlockingKineticConnection> con;
  kinetic::KineticConnectionFactory factory = kinetic::NewKineticConnectionFactory();
  if (factory.NewThreadsafeBlockingConnection(config.connectionOptions, con, 5).notOk()) {
    std::cout << "Failed creating connection." << std::endl;
    return EXIT_FAILURE;
  }

  if (config.operations.erase(OpType::scan)) {
    std::unique_ptr<string> last_handled;
    std::unique_ptr<std::vector<string>> faulty;
    if (!con->MediaScan(config.start_key, true, config.end_key, true, 100,
                        last_handled, faulty).ok() || !last_handled) {
      std::cout << "Failed MediaScan request" << std::endl;
      return EXIT_FAILURE;
    }

    auto num_faulty = (faulty ? faulty->size() : 0);
    std::cout << num_faulty << " keys reported as corrupt. (checked until key " << *last_handled << ")" << std::endl;
    if (faulty) {
      for (auto key_it = faulty->cbegin(); key_it != faulty->cend(); key_it++) {
        std::cout << *key_it << std::endl;
      }
    }
  }

  if (config.operations.erase(OpType::optimize)) {
    std::unique_ptr<string> last_handled;
    if(! con->MediaOptimize(config.start_key, true, config.end_key, true,
                            last_handled).ok() || !last_handled) {
      std::cout << "Failed MediaOptimize request" << std::endl;
      return EXIT_FAILURE;
    }
    std::cout << "MediaOptimize complete (optimized until key" << *last_handled << ")" << std::endl;
  }

  if (!config.operations.empty()) {
    keybased_operation(config, con);
  }
  return EXIT_SUCCESS;
}

