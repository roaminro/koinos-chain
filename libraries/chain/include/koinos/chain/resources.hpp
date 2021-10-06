#pragma once

#include <koinos/chain/chain.pb.h>

#include <memory>

namespace koinos::chain {

namespace compute_load {
   constexpr uint64_t light  = 100;
   constexpr uint64_t medium = 1000;
   constexpr uint64_t heavy  = 10000;
}

class rc_session final
{
public:
   rc_session( uint64_t begin_rc );
   ~rc_session();

   void use( uint64_t rc );
   uint64_t remaining();
   uint64_t used();

private:
   uint64_t _begin_rc;
   uint64_t _end_rc;
};

class resource_meter final
{
public:
   resource_meter();
   ~resource_meter();

   void set_resource_limit_data( const resource_limit_data& rld );

   std::shared_ptr< rc_session > make_session( uint64_t rc );

   void use_disk_storage( uint64_t bytes );
   uint64_t disk_storage_used();
   uint64_t disk_storage_remaining();

   void use_network_bandwidth( uint64_t bytes );
   uint64_t network_bandwidth_used();
   uint64_t network_bandwidth_remaining();

   void use_compute_bandwidth( uint64_t ticks );
   uint64_t compute_bandwidth_used();
   uint64_t compute_bandwidth_remaining();

private:
   uint64_t _disk_storage_remaining      = 0;
   uint64_t _network_bandwidth_remaining = 0;
   uint64_t _compute_bandwidth_remaining = 0;
   resource_limit_data _resource_limit_data;
   std::weak_ptr< rc_session > _session;
};

} // koinos::chain
