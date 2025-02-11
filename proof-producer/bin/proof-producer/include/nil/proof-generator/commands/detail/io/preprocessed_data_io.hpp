#pragma once

#include <memory>

#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>


namespace nil {
    namespace proof_producer {

        template <typename CurveType, typename HashType>
        struct PreprocessedPublicDataIO {
            using Types = TypeSystem<CurveType, HashType>;
            using Endianness = typename Types::Endianness;
            using TTypeBase = typename Types::TTypeBase;
            using PublicPreprocessedData = typename Types::PublicPreprocessedData;
            using CommonData = typename Types::CommonData;

            struct Writer: public command_step
            {
                Writer(
                    resources::resource_provider<PublicPreprocessedData>& public_preprocessed_data_provider,
                    const boost::filesystem::path& preprocessed_data_file
                ): preprocessed_data_file_(preprocessed_data_file)
                {
                    resources::subscribe_value<PublicPreprocessedData>(public_preprocessed_data_provider, public_preprocessed_data_);
                }

                CommandResult execute() override {
                    using namespace nil::crypto3::marshalling::types;

                    BOOST_ASSERT(public_preprocessed_data_);

                    BOOST_LOG_TRIVIAL(info) << "Writing all preprocessed public data to " <<
                        preprocessed_data_file_;

                    auto marshalled_preprocessed_public_data =
                        fill_placeholder_preprocessed_public_data<Endianness, PublicPreprocessedData>(
                            *public_preprocessed_data_
                        );
                    bool res = detail::encode_marshalling_to_file(
                        preprocessed_data_file_,
                        marshalled_preprocessed_public_data
                    );
                    if (!res) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to write preprocessed public data");
                    }
                    BOOST_LOG_TRIVIAL(info) << "Preprocessed public data written.";

                    return CommandResult::Ok();
                }

            private:
                std::shared_ptr<PublicPreprocessedData> public_preprocessed_data_;
                boost::filesystem::path preprocessed_data_file_;
            };

            struct Reader:
                public command_step,
                public resources::resources_provider<PublicPreprocessedData, CommonData>
            {
                Reader(const boost::filesystem::path& preprocessed_data_file):
                    preprocessed_data_file_(preprocessed_data_file)
                {}

                CommandResult execute() override {
                    BOOST_LOG_TRIVIAL(info) << "Read preprocessed data from " << preprocessed_data_file_;

                    using namespace nil::crypto3::marshalling::types;
                    using resources::notify;

                    using PublicPreprocessedDataMarshalling =
                        placeholder_preprocessed_public_data<TTypeBase, PublicPreprocessedData>;

                    auto marshalled_value = detail::decode_marshalling_from_file<PublicPreprocessedDataMarshalling>(
                        preprocessed_data_file_);
                    if (!marshalled_value) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to read preprocessed data from {}" , preprocessed_data_file_.string());
                    }

                    auto public_preprocessed_data = make_placeholder_preprocessed_public_data<Endianness, PublicPreprocessedData>(*marshalled_value);
                    auto data_ptr = std::make_shared<PublicPreprocessedData>(std::move(public_preprocessed_data));
                    notify<PublicPreprocessedData>(*this, data_ptr);
                    notify<CommonData>(*this, data_ptr->common_data);

                    return CommandResult::Ok();
                }

            private:
                boost::filesystem::path preprocessed_data_file_;
            };

            struct CommonDataWriter: public command_step {

                CommonDataWriter(
                    resources::resource_provider<CommonData>& public_data_provider,
                    const boost::filesystem::path& preprocessed_common_data_file
                ): preprocessed_common_data_file_(preprocessed_common_data_file)
                {
                    resources::subscribe_value<CommonData>(public_data_provider, common_data_);
                }

                CommandResult execute() override {
                    BOOST_ASSERT(common_data_);

                    BOOST_LOG_TRIVIAL(info) << "Writing preprocessed common data to " << preprocessed_common_data_file_;
                    auto marshalled_common_data =
                        nil::crypto3::marshalling::types::fill_placeholder_common_data<Endianness, CommonData>(*common_data_);

                    bool res = detail::encode_marshalling_to_file(
                        preprocessed_common_data_file_,
                        marshalled_common_data
                    );
                    if (!res) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to write preprocessed common data");
                    }

                    BOOST_LOG_TRIVIAL(info) << "Preprocessed common data written.";
                    return CommandResult::Ok();
                }

            private:
                std::shared_ptr<CommonData> common_data_;
                boost::filesystem::path preprocessed_common_data_file_;
            };

            struct CommonDataReader:
                public command_step,
                public resources::resource_provider<CommonData>
             {
                CommonDataReader(const boost::filesystem::path& preprocessed_common_data_file):
                    preprocessed_common_data_file_(preprocessed_common_data_file)
                {}

                CommandResult execute() override {
                    BOOST_LOG_TRIVIAL(info) << "Read preprocessed common data from " << preprocessed_common_data_file_;

                    using resources::notify;
                    using CommonDataMarshalling = nil::crypto3::marshalling::types::placeholder_common_data<TTypeBase, CommonData>;

                    auto marshalled_value = detail::decode_marshalling_from_file<CommonDataMarshalling>(
                        preprocessed_common_data_file_);

                    if (!marshalled_value) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to read preprocessed common data from {}", preprocessed_common_data_file_.string());
                    }

                    auto common_data = nil::crypto3::marshalling::types::make_placeholder_common_data<Endianness, CommonData>(*marshalled_value);
                    notify(*this, std::move(common_data));

                    return CommandResult::Ok();
                }

            private:
                boost::filesystem::path preprocessed_common_data_file_;
            };
        };
    } // namespace proof_producer
} // namespace nil
