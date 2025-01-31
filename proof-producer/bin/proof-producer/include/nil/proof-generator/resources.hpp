#pragma once

#include <boost/signals2.hpp>
#include <functional>
#include <initializer_list>
#include <memory>


namespace resources {

    template <typename Resource>
    class resource_provider {
    public:
        using ResourcePtr = std::shared_ptr<Resource>;
        using Signal = boost::signals2::signal<void(ResourcePtr)>;
        using SlotType = Signal::slot_type;

        resource_provider() = default;
        resource_provider(const resource_provider&) = delete;
        resource_provider& operator=(const resource_provider&) = delete;
        resource_provider(resource_provider&&) = default;
        resource_provider& operator=(resource_provider&&) = default;
        
        virtual ~resource_provider() = default;

        Signal sig_impl_; // TODO make me private
    };

    template <typename... Resources> 
    class resources_provider: public resource_provider<Resources>... {};

    template <typename T, typename... Resources> 
    concept ProvidesAll = (std::is_base_of_v<resource_provider<Resources>, T> && ...);

    template <typename Resource>
    void notify(resource_provider<Resource>& provider, typename resource_provider<Resource>::ResourcePtr resource) {
        provider.sig_impl_(resource);
    }

    // connects passed slot to the signal of the provider (slot is something invokable with the same signature as the signal)
    template <typename Resource>
    void subscribe(resource_provider<Resource>& provider, const typename resource_provider<Resource>::SlotType& slot) {
        provider.sig_impl_.connect(slot);  
    }

    // connects passed value (class field usually) to the signal of the provider via lambda
    template <typename Resource>
    void subscribe_value(resource_provider<Resource>& provider, typename resource_provider<Resource>::ResourcePtr& resource) {
        subscribe(provider,[&resource](typename resource_provider<Resource>::ResourcePtr value) {
            resource = value;
        });
    }

    template <typename Resource>
    void subscribe_values(
        resource_provider<Resource>& provider, 
        std::initializer_list<
            std::reference_wrapper<
                typename resource_provider<Resource>::ResourcePtr
            >
        > resources) 
    {
        for (auto& resource : resources) {
            subscribe_value(provider, resource);
        }
    }

} // namespace resources
