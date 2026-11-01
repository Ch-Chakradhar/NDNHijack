#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <iostream>
#include <curl/curl.h>
#include <algorithm>

using namespace ndn;
using namespace std;

constexpr size_t MAX_SEGMENT_SIZE = 8000;

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    static_cast<std::string*>(userp)->append(static_cast<const char*>(contents), totalSize);
    return totalSize;
}

std::string http_get_request(std::string url) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "libcurl error: " << curl_easy_strerror(res) << std::endl;
        }
        curl_easy_cleanup(curl);
    }
    return response;
}

Face m_face{};
KeyChain m_keyChain{};

static std::map<Name, std::vector<std::shared_ptr<Data>>> g_segment_cache;

void onInterest(const InterestFilter& interest_filter, const Interest& interest) {
    std::cout << "Got Interest - " << interest << std::endl;
    const Name& name = interest.getName();

    if (!name.empty() && name[-1].isSegment()) {
        size_t segNo = static_cast<size_t>(name[-1].toSegment());
        Name versionedPrefix = name.getPrefix(-1);

        auto it = g_segment_cache.find(versionedPrefix);
        if (it != g_segment_cache.end() && segNo < it->second.size()) {
            std::cout << "Serving cached segment " << segNo << " for " << versionedPrefix << std::endl;
            m_face.put(*(it->second[segNo]));
            return;
        }

        std::cerr << "Segment " << segNo << " not found for " << versionedPrefix << std::endl;
        return;
    }

    size_t host_idx = (name.size() > 2 && name.get(1).toUri() == "test") ? 2 : 1;
    std::string host = name.size() > host_idx ? name.get(host_idx).toUri() : "unknown";
    std::string path = "/";
    for (size_t i = host_idx + 1; i < name.size(); ++i) {
        path += name.get(i).toUri();
        if (i + 1 < name.size()) {
            path += "/";
        }
    }

    std::string request = "http://" + host + path;
    std::string response = http_get_request(request);

    if (response.size() <= MAX_SEGMENT_SIZE) {
        auto data = std::make_shared<Data>();
        data->setName(interest.getName());
        data->setFreshnessPeriod(10_s);
        data->setContent(make_span(reinterpret_cast<const uint8_t*>(response.data()), response.size()));

        m_keyChain.sign(*data);
        std::cout << "Sending single unsegmented Data packet (" << response.size() << " bytes)" << std::endl;
        m_face.put(*data);
        return;
    }

    size_t total_segments = (response.size() + MAX_SEGMENT_SIZE - 1) / MAX_SEGMENT_SIZE;
    Name versionedPrefix = Name(name).appendVersion();
    auto finalBlock = name::Component::fromSegment(total_segments - 1);

    std::vector<std::shared_ptr<Data>> segments;
    segments.reserve(total_segments);

    for (size_t i = 0; i < total_segments; ++i) {
        size_t offset = i * MAX_SEGMENT_SIZE;
        size_t len = std::min(MAX_SEGMENT_SIZE, response.size() - offset);

        auto data = std::make_shared<Data>();
        data->setName(Name(versionedPrefix).appendSegment(i));
        data->setFreshnessPeriod(10_s);
        data->setFinalBlock(finalBlock);
        data->setContent(make_span(reinterpret_cast<const uint8_t*>(response.data() + offset), len));

        m_keyChain.sign(*data);
        segments.push_back(data);
    }

    g_segment_cache[versionedPrefix] = segments;

    std::cout << "Sending Segment 0 of " << total_segments << " for " << versionedPrefix << std::endl;
    m_face.put(*segments[0]);
}

int main(int argc, char** argv) {
    curl_global_init(CURL_GLOBAL_ALL);
    m_face.setInterestFilter("/ndn-test/test", onInterest,
        [](const Name& prefix, const std::string& reason) {
            std::cerr << "Failed to register prefix " << prefix << ": " << reason << std::endl;
        }
    );

    auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
    m_face.setInterestFilter(
        security::extractIdentityFromCertName(cert.getName()),
        [cert](const InterestFilter& interest_filter, const Interest& interest) {
            if (interest.matchesData(cert)) {
                m_face.put(cert);
            }
        });

    m_face.processEvents();
    return 0;
}
