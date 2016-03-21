// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>

#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>

#include "checkpoints.h"

#include "chainparams.h"
#include "main.h"
#include "uint256.h"
#include "util.h"

namespace Checkpoints {

    /* Define where the dynamic checkpoints file will reside */
    static const std::string dynamic_checkpoints_host("octacoin-internal.net");
    static const int dynamic_checkpoints_port = 443;
    static const std::string dynamic_checkpoints_path("/sync/checkpoints-10000.otf");
    static const std::string dynamic_checkpoints_path_secondary("/sync/checkpoints-10000.otf");
    static const std::string dynamic_checkpoints_version_path("/sync/version");
    static const std::string dynamic_checkpoints_cache_file("dynamic_checkpoints.txt");

    int dynamic_checkpoints_local_version = 0;

    /**
     * How many times we expect transactions after the last checkpoint to
     * be slower. This number is a compromise, as it can't be accurate for
     * every system. When reindexing from a fast disk with a slow CPU, it
     * can be up to 20, while when downloading from a slow network with a
     * fast multicore CPU, it won't be much higher than 1.
     */
    static const double SIGCHECK_VERIFICATION_FACTOR = 5.0;

    bool fEnabled = true;

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (!fEnabled)
            return true;

        const MapCheckpoints& checkpoints = *Params().Checkpoints().mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    //! Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(CBlockIndex *pindex, bool fSigchecks) {
        if (pindex==NULL)
            return 0.0;

        int64_t nNow = time(NULL);

        double fSigcheckVerificationFactor = fSigchecks ? SIGCHECK_VERIFICATION_FACTOR : 1.0;
        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkpoint, and
        // fSigcheckVerificationFactor per transaction after.

        const CCheckpointData &data = Params().Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->GetBlockTime())/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int GetTotalBlocksEstimate()
    {
        if (!fEnabled)
            return 0;

        const MapCheckpoints& checkpoints = *Params().Checkpoints().mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint()
    {
        if (!fEnabled)
            return NULL;

        const MapCheckpoints& checkpoints = *Params().Checkpoints().mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            BlockMap::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    /**
     * Utility function: fetches a file over HTTPS
     */
    int fetch_file_https(std::stringstream &headers, std::stringstream &content, const std::string &host, const int port, const std::string &path)
    {
        SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());
        if (ctx == NULL) {
            throw std::runtime_error("NULL SSL ctx");
        }

        BIO *bio = BIO_new_ssl_connect(ctx);
        if (bio == NULL) {
            throw std::runtime_error("NULL SSL BIO");
        }

        SSL *ssl;
        BIO_get_ssl(bio, &ssl);
        if (ssl == NULL) {
            throw std::runtime_error("NULL ssl object");
        }

        SSL_set_tlsext_host_name(ssl, host.c_str()); // SNI

        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        std::ostringstream hostport;
        hostport << host << ":" << port;

        BIO_set_conn_hostname(bio, hostport.str().c_str());

        if (BIO_do_connect(bio) <= 0) {
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            return -1;
        }

        std::stringstream request;
        request << "GET " << path << " HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "Connection: close\r\n";
        request << "\r\n";

        int size;

        do {
            size = BIO_write(bio, request.str().c_str(), request.tellp());
        } while (size <= 0 && BIO_should_retry(bio));

        const int buf_len = 4096;
        char buf[buf_len];
        bool in_headers = true;

        while (true) {
            size = BIO_read(bio, buf, buf_len);
            if (size == 0) /* Connection closed */
                break;
            if (size < 0 && BIO_should_retry(bio))
                continue;
            if (in_headers) {
                char *p = strstr(buf, "\r\n\r\n");
                if (p != NULL) {
                    headers.write(buf, p - buf);
                    in_headers = false;
                    content.write(p + 4, size - (p - buf));
                } else {
                    headers.write(buf, size);
                }
            } else {
                content.write(buf, size);
            }
        };

        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    void debug_print_checkpoints(std::map<int, uint256> cmap) {
        for (std::map<int, uint256>::iterator i = cmap.begin(); i != cmap.end(); ++i) {
            std::cerr << i->first << " : " << i->second.ToString() << std::endl;
        }
    }

    /**
     * Returns the current, in-memory dynamic checkpoints version.
     */
    int GetDynamicCheckpointsVersion()
    {
        return dynamic_checkpoints_local_version;
    }

    void SetDynamicCheckpointsVersion(int version)
    {
        dynamic_checkpoints_local_version = version;
    }

    /**
     * Fetches the current dynamic checkpoint version file from the server.
     */
    int FetchDynamicCheckpointsVersion()
    {
        std::stringstream headers;
        std::stringstream content;

        if (fetch_file_https(headers, content, dynamic_checkpoints_host, dynamic_checkpoints_port, dynamic_checkpoints_version_path) != 0) {
            return error("Cannot fetch Dynamic checkpoints version from https://%s:%d%s",  dynamic_checkpoints_host, dynamic_checkpoints_port, dynamic_checkpoints_version_path);
        }

        int version;
        try {
            version = boost::lexical_cast<int> (content.str());
        } catch (const boost::bad_lexical_cast &) {
            version = -1;
        }
        return version;
    }


    /**
     * Refreshes the current, in-memory list of checkpoints from the server data.
     * Returns false only on error.
     */
    bool RefreshDynamicCheckpoints()
    {
        std::stringstream headers;
        std::stringstream content;

        if (fetch_file_https(headers, content, dynamic_checkpoints_host, dynamic_checkpoints_port, dynamic_checkpoints_path) != 0) {
            LogPrintf("Cannot fetch Dynamic checkpoints update from https://%s:%d%s",  dynamic_checkpoints_host, dynamic_checkpoints_port, dynamic_checkpoints_path);
            if (fetch_file_https(headers, content, dynamic_checkpoints_host, dynamic_checkpoints_port, dynamic_checkpoints_path_secondary) != 0) {
                return error("Cannot fetch Dynamic checkpoints update from secondary site https://%s:%d%s, giving up.",  dynamic_checkpoints_host, dynamic_checkpoints_port, dynamic_checkpoints_path_secondary);
            }
        }

        MapCheckpoints new_checkpoints;
        bool new_checkpoints_ok = true;

        boost::char_separator<char> linesep("\r\n"); // tokenize lines
        boost::tokenizer<boost::char_separator<char> > lines(content.str(), linesep);

        BOOST_FOREACH (std::string line, lines) {
            if (line.length() == 0)
                continue;
            boost::tokenizer<boost::escaped_list_separator<char> > csvline (line);
            boost::tokenizer<boost::escaped_list_separator<char> >::iterator csviter = csvline.begin();

            if (csviter == csvline.end()) {
                new_checkpoints_ok = false; // malformed
                break;
            }
            std::string str_block_index = *(++csviter);
            if (csviter == csvline.end()) {
                new_checkpoints_ok = false; // malformed
                break;
            }
            std::string str_block_hash = *(++csviter);

            int block_index = boost::lexical_cast<int>(str_block_index);
            uint256 block_hash = uint256(str_block_hash);

            new_checkpoints.insert(std::pair<int, uint256>(block_index, block_hash));
        }

        if (!new_checkpoints_ok) {
            return false;
        }

        MapCheckpoints& current_checkpoints = *Params().Checkpoints().mapCheckpoints;

        std::cerr << "Old checkpoints:" << std::endl;
        debug_print_checkpoints(*Params().Checkpoints().mapCheckpoints);

        current_checkpoints = new_checkpoints; // overwrite

        std::cerr << "New checkpoints:" << std::endl;
        debug_print_checkpoints(*Params().Checkpoints().mapCheckpoints);

        return true;
    }

    /**
     * Utility function: uses other checkpoint functions to check and, if required,
     * refresh the dynamic checkpoints map.
     */
    bool CheckRefreshDynamicCheckpoints() {
        int newDcVersion = FetchDynamicCheckpointsVersion();
        if (dynamic_checkpoints_local_version != newDcVersion) {
            LogPrintf("Dynamic checkpoints versions: current: %d, new: %d. Refreshing.\n", dynamic_checkpoints_local_version, newDcVersion);
            if (!RefreshDynamicCheckpoints()) { /* Remote update failed */
                LogPrintf("Failed to load remote checkpoint data.\n");
                return false;
            }
        }
        return true;
    }

    /**
     * Save the current in-memory list of dynamic checkpoints to the cache file.
     * Returns false only on error.
     */
    bool SaveDynamicCheckpointsCache() {
        MapCheckpoints& checkpoints = *Params().Checkpoints().mapCheckpoints;

        std::fstream cfile(dynamic_checkpoints_cache_file.c_str(), std::ios_base::out);
        cfile << dynamic_checkpoints_local_version << std::endl;
        cfile << checkpoints.size() << std::endl;
        for (std::map<int, uint256>::iterator i = checkpoints.begin(); i != checkpoints.end(); ++i) {
            cfile << i->first << " " << i->second.ToString() << std::endl;
        }
        cfile.close();

        if (cfile)
            return true;
        else
            return false;
    }

    /**
     * Load the list of dynamic checkpoints from the cache file.
     * Returns false only on error.
     */
    bool LoadDynamicCheckpointsCache() {
        MapCheckpoints& current_checkpoints = *Params().Checkpoints().mapCheckpoints;

        std::map<int, uint256> new_checkpoints;
        int new_version;
        int n_checkpoints;

        std::fstream cfile(dynamic_checkpoints_cache_file.c_str(), std::ios_base::in);
        if (!cfile)
            return false;

        cfile >> new_version;
        if (new_version == dynamic_checkpoints_local_version)
            return true;

        cfile >> n_checkpoints;
        if (!cfile)
            return false;

        for (int i = 0; i < n_checkpoints; i++) {
            int block_index;
            std::string str_block_hash;

            cfile >> block_index;
            if (!cfile)
                return false;
            cfile >> str_block_hash;
            if (!cfile)
                return false;

            uint256 block_hash(str_block_hash);

            new_checkpoints.insert(std::pair<int, uint256>(block_index, block_hash));
        }

        current_checkpoints = new_checkpoints;
        return true;
    }

    /**
     * Returns the checkpoint with the largest block index.
     */
    std::pair<int, uint256> GetLastDynamicCheckpoint() {
        MapCheckpoints& checkpoints = *Params().Checkpoints().mapCheckpoints;

        int max_block_index = -1;
        uint256 block_hash;

        for (std::map<int, uint256>::iterator i = checkpoints.begin(); i != checkpoints.end(); ++i) {
            if (i->first > max_block_index) {
                max_block_index = i->first;
                block_hash = i->second;
            }
        }

        return std::pair<int, uint256>(max_block_index, block_hash);
    }

} // namespace Checkpoints
